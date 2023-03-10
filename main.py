#!/usr/bin/env python3
# coding: utf-8

import fire
import re
import yaml
import gzip
import time
from typing import Literal
from xdbSearcher import XdbSearcher
from os.path import join, dirname, exists, splitext
from utils import init_logging, spinner_context, get_file_line_count
from dataclasses import dataclass
from collections.abc import Callable
from pyecharts import options as opts
from pyecharts.charts import Map, Geo
from pyecharts.faker import Faker
from pyecharts.globals import ChartType


@dataclass
class NamedQueryResult:
    datetime: str
    ip: str
    view: str
    domain: str
    type: str
    name_server: str

    def from_dict(dict_value):
        return NamedQueryResult(**dict_value)


@dataclass
class NamedQueryResultExtra:
    ip: str
    info: list[NamedQueryResult]
    geolocation: dict


@dataclass
class Filter:
    key: str
    value: str
    fn: Callable[[str, str, dict], bool]


@dataclass
class RecordItem:
    ip: str
    count: int
    datetime: list[str]
    geolocation: dict
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'count': self.count,
            'datetime': self.datetime,
            'geolocation': self.geolocation
        }

@dataclass
class Report:
    domain: str
    total: int
    records: list[RecordItem]
    
    def to_dict(self):
        return {
            'domain': self.domain,
            'total': self.total,
            'records': list(map(lambda record: record.to_dict(), self.records))
        }
    
    def sort_by_count(self):
        self.records.sort(key=lambda record: record.count, reverse=True)
        return self
    
    def sort_by_datetime(self):
        self.records.sort(key=lambda record: record.datetime[0], reverse=True)
        return self
    
    def aggregate_by_provinces(self, only_show_china=True):
        provinces_count: dict[str, int] = {}
        for record in self.records:
            # ignore the ip without geolocation
            if (record.geolocation is None) or (only_show_china and record.geolocation['country'] != '??????'):
                continue
            elif record.geolocation['province'] not in provinces_count:
                provinces_count[record.geolocation['province']] = record.count
            else:
                provinces_count[record.geolocation['province']] += record.count
        return provinces_count
    
    def make_map(self, map_path, only_show_china=True):
        map_data = self.aggregate_by_provinces(only_show_china)
        map_data = list(zip(map_data.keys(), map_data.values()))
        logger.info(f'generate map data: {map_data}')
        if len(map_data) == 0:
            logger.info(f'no map data to generate, skip!')
            return
        c = Map().add("", map_data, "china").set_global_opts(title_opts=opts.TitleOpts(title="DNS???????????????-??????????????????"))
        # c = (
        #     Geo(is_ignore_nonexistent_coord=True)
        #     .add_schema(maptype="china")
        #     .add(
        #         "DNS???????????????",
        #         map_data,
        #         type_=ChartType.HEATMAP,
        #     )
        #     .set_series_opts(
        #         label_opts=opts.LabelOpts(is_show=True),
        #     )
        #     .set_global_opts(
        #         visualmap_opts=opts.VisualMapOpts(),
        #         title_opts=opts.TitleOpts(title="??????????????????"),
        #     )
        # )
        c.render(map_path)

    @staticmethod
    def load_data_via_deserialize(report_path: str = None):
        with open(report_path, 'r', encoding='utf-8') as yamlfile:
            dict_values = yaml.load(yamlfile, Loader=yaml.FullLoader)
        logger.info(f'load data from {report_path}')
        kargs = {**dict_values, "records": list(map(lambda record: RecordItem(**record), dict_values['records']))}
        report = Report(** kargs)
        return report
    
    @staticmethod
    def save_data_via_serialize(dict_values, report_path: str = None):
        with open(report_path, 'w', encoding='utf-8') as yamlfile:
            # https://matthewpburruss.com/post/yaml/
            # convert the report object to dict then dump to yaml to avoid the yaml tag
            yaml.dump(dict_values, yamlfile, sort_keys=False,
                    indent=2, allow_unicode=True)

logger = init_logging()


class SearchIPGeolocation:
    _inner_cache = {}

    def __init__(self, dbPath=join(dirname(__file__), 'data', 'ip2region.xdb')) -> None:
        self.dbPath = dbPath
        self.searcher = XdbSearcher(
            contentBuff=XdbSearcher.loadContentFromFile(dbfile=self.dbPath))

    def search(self, ip):
        try:
            if ip not in self._inner_cache:
                self._inner_cache[ip] = self.searcher.searchByIPStr(ip)
            return self._inner_cache[ip]
        except Exception as e:
            logger.error(f'Error when search ip: {ip}, error: {e}')
            return None

    def close(self):
        self.searcher.close()


class NamedQueryLogParser:

    def __init__(self, query_log_path, filters: list[Filter] = []) -> None:
        # check if the file exists
        if not exists(query_log_path):
            raise FileNotFoundError(f'File {query_log_path} not found')
        self.query_log_path = query_log_path
        self.filters = filters

    def _filter(self, match_dict):
        for filter in self.filters:
            match = filter.fn(filter.key, filter.value, match_dict)
            if not match:
                return False
        return True

    def parse(self):
        regex = re.compile(r'(?P<datetime>.*?) queries: info: client @[0-9a-fx]* (?P<ip>[\w.]*)#\d+ \(.*\): view (?P<view>\w+): query: (?P<domain>[\w.-]+) IN (?P<type>\w+) .*? \((?P<name_server>[\w.]+)\)')
        named_query_results: list[NamedQueryResult] = []
        # calculate the file lines of the file_input
        with spinner_context('Calculate file line count ...') as spinner:
            file_input_lines = get_file_line_count(self.query_log_path)
        logger.info(
            f'file_input: {self.query_log_path}, lines: {file_input_lines}')
        start_time = time.perf_counter_ns()
        open_fn = gzip.open if self.query_log_path.endswith('.gz') else open
        with spinner_context(f'Processing {self.query_log_path}...') as spinner, open_fn(self.query_log_path, 'rt', encoding='utf-8') as f:
            # update the spinner text to show the progress in 00.01% minimum
            update_tick = int(file_input_lines /
                              10000 if file_input_lines > 10000 else 10)
            for index, line in enumerate(f):
                match = re.search(regex, line)
                if match:
                    match_dict = match.groupdict()
                    if self._filter(match_dict):
                        logger.debug(f'Found matched log {match_dict}')
                        named_query_results.append(
                            NamedQueryResult.from_dict(match_dict))
                if index > 0 and index % update_tick == 0:
                    current_finish_rate = index / file_input_lines
                    expected_finish_time_in_seconds = (time.perf_counter_ns() - start_time) / (current_finish_rate) * (1 - current_finish_rate) / 1e9
                    spinner.text = f'Processing {current_finish_rate * 100:6.2f}%, Found {len(named_query_results):{len(str(file_input_lines))}} of {file_input_lines} matched logs currently, expected finish in {expected_finish_time_in_seconds:6.2f}s'
        logger.info(f'Found {len(named_query_results)} matched logs')
        return named_query_results

    def aggregate_by_source_ip(self, named_query_results: list[NamedQueryResult], search_ip_geolocation: SearchIPGeolocation):
        with spinner_context(f'Aggregate named_query_results by source ip ...') as spinner:
            named_query_result_extras: dict[str, NamedQueryResultExtra] = {}
            for named_query_result in named_query_results:
                if named_query_result.ip not in named_query_result_extras:
                    named_query_result_extras[named_query_result.ip] = NamedQueryResultExtra(
                        named_query_result.ip, [named_query_result], search_ip_geolocation.search(named_query_result.ip))
                else:
                    named_query_result_extras[named_query_result.ip].info.append(
                        named_query_result)
            results = [*named_query_result_extras.values()]
            spinner.text = f'Aggregate finished, for {len(named_query_results)} matched logs, produced {len(results)} named_query_result_extras'
        return results

    def make_simple_report(self, named_query_result_extras: list[NamedQueryResultExtra]):
        with spinner_context(f'Make simple report ...') as spinner:
            records = list(map(lambda named_query_result_extra: RecordItem(named_query_result_extra.ip, len(
                named_query_result_extra.info), list(map(lambda info: info.datetime, named_query_result_extra.info)), named_query_result_extra.geolocation), named_query_result_extras))
            report = Report(self.filters[0].value, sum(map(lambda record: record.count, records)), records)
            spinner.text = f'Make simple report finished'
        return report


def _make_filters(filter_domain, fuzzy_search):
    # make filters
    filters = []
    # works
    # def _domain_filter(key, value, match_dict):
    #     return value in match_dict[key] if fuzzy_search else value == match_dict[key]
    # domain_filter = Filter('domain', filter_domain, _domain_filter) 
    # conditional expression has higher precedence than lambda expression
    # fn = lambda: "l1" if condition else lambda: "l2" is equivalent to fn = lambda: ("l1" if condition else "l2")
    # https://docs.python.org/3/reference/expressions.html#operator-precedence
    # fn = (lambda key, value, match_dict: value in match_dict[key]) if fuzzy_search else (lambda key, value, match_dict: value == match_dict[key])
    # domain_filter = Filter('domain', filter_domain, fn)
    domain_filter = Filter('domain', filter_domain, lambda key, value, match_dict: value in match_dict[key] if fuzzy_search else value == match_dict[key])
    filters.append(domain_filter)
    return filters


def main(query_log_path=join(dirname(__file__), 'test.log'),
         dbPath=join(dirname(__file__), 'data', 'ip2region.xdb'),
         filter_domain='www.jwc.ynu.edu.cn',
         report_path='report.yaml',
         sort_by: Literal['count', 'datetime']='count',
         map_path='map.html',
         use_old_report_if_available=True,
         fuzzy_search=False,
         only_show_china=True,
         report_outline_path='report.outline.txt',
         report_file_name_suffix='',
    ):
    # normalize report_path, report_outline_path with report_file_name_suffix
    if report_file_name_suffix:
        report_path_file_name, report_path_file_ext = splitext(report_path)
        report_outline_path_file_name, report_outline_path_file_ext = splitext(report_outline_path)
        report_path = f'{report_path_file_name}_{report_file_name_suffix}{report_path_file_ext}'
        report_outline_path = f'{report_outline_path_file_name}_{report_file_name_suffix}{report_outline_path_file_ext}'
    if use_old_report_if_available and exists(report_path):
        logger.info(f'Use old report {report_path}')
        report = Report.load_data_via_deserialize(report_path)
    else:
        logger.info(f'Create fresh report {report_path}')
        search_ip_geolocation = SearchIPGeolocation(dbPath)
        filters = _make_filters(filter_domain, fuzzy_search)
        named_query_log_parser = NamedQueryLogParser(query_log_path, filters)
        named_query_results = named_query_log_parser.parse()
        named_query_result_extras = named_query_log_parser.aggregate_by_source_ip(
            named_query_results, search_ip_geolocation)
        report = named_query_log_parser.make_simple_report(
            named_query_result_extras)
        with spinner_context(f'Sort report by {sort_by} ...') as spinner:
            if sort_by == 'count':
                report.sort_by_count()
            elif sort_by == 'datetime':
                report.sort_by_datetime()
            spinner.text = f'Sort report finished'
        # logger and save report outline in (province, count) form, sort by count
        provinces_count = report.aggregate_by_provinces(only_show_china)
        provinces_count = list(provinces_count.items())
        provinces_count.sort(key=lambda entry: entry[1], reverse=True)
        report_outlines_content = '\n'.join(map(lambda record: f'{record[0]}, {record[1]}', provinces_count))
        logger.debug(report_outlines_content)
        with spinner_context(f'Write report outline to {report_outline_path} ...') as spinner, open(report_outline_path, 'w', encoding='utf-8') as f:
            f.write(report_outlines_content)
            spinner.text = f'Write report outline finished'
        with spinner_context(f'Write report to {report_path} ...') as spinner:
            Report.save_data_via_serialize(report.to_dict(), report_path)
            spinner.text = f'Write report finished'
    # use pyecharts to generate the map
    with spinner_context(f'Generate map to {map_path} ...') as spinner:
        report.make_map(map_path, only_show_china)
        spinner.text = f'Generate map finished'


if __name__ == '__main__':
    fire.core.Display = lambda lines, out: print(*lines, file=out)
    fire.Fire(main)
