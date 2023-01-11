from typing import Literal
import fire
from xdbSearcher import XdbSearcher
from os.path import join, dirname, exists
from utils import init_logging, spinner_context, get_file_line_count
from dataclasses import dataclass
from collections.abc import Callable
import re
import yaml
import gzip


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



logger = init_logging()


class SearchIPGeolocation:
    _inner_cache = {}

    def __init__(self, dbPath=join(dirname(__file__), 'data', 'ip2region.xdb')) -> None:
        self.dbPath = dbPath
        self.searcher = XdbSearcher(
            contentBuff=XdbSearcher.loadContentFromFile(dbfile=self.dbPath))

    def search(self, ip):
        if ip not in self._inner_cache:
            self._inner_cache[ip] = self.searcher.searchByIPStr(ip)
        return self._inner_cache[ip]

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
            if not filter.fn(filter.key, filter.value, match_dict):
                return False
        return True

    def parse(self):
        regex = r'(?P<datetime>.*?) queries: info: client @[0-9a-fx]* (?P<ip>[0-9.:]*)#\d+ \(.*\): view (?P<view>\w+): query: (?P<domain>[\w.]+) IN (?P<type>\w+) .*? \((?P<name_server>[0-9.:]+)\)'
        named_query_results: list[NamedQueryResult] = []
        # calculate the file lines of the file_input
        with spinner_context('Calculate file line count ...') as spinner:
            file_input_lines = get_file_line_count(self.query_log_path)
        logger.info(
            f'file_input: {self.query_log_path}, lines: {file_input_lines}')
        open_fn = gzip.open if self.query_log_path.endswith('.gz') else open
        with spinner_context(f'Processing {self.query_log_path}...') as spinner, open_fn(self.query_log_path, 'rt', encoding='utf-8') as f:
            # update the spinner text to show the progress in 00.01% minimum
            update_tick = int(file_input_lines /
                              1000 if file_input_lines > 1000 else 100)
            for index, line in enumerate(f):
                match = re.search(regex, line)
                if match:
                    match_dict = match.groupdict()
                    if self._filter(match_dict):
                        logger.debug(f'Found matched log {match_dict}')
                        named_query_results.append(
                            NamedQueryResult.from_dict(match_dict))
                if index % update_tick == 0:
                    spinner.text = f'Processing {index / file_input_lines * 100:.2f}%'
        logger.info(f'Found {len(named_query_results)} matched logs')
        return named_query_results

    def aggregate_by_source_ip(self, named_query_results: list[NamedQueryResult], search_ip_geolocation: SearchIPGeolocation):
        # named_query_result_extras = list(map(lambda named_query_result: NamedQueryResultExtra(named_query_result.domain, named_query_result, search_ip_geolocation.search(
        #     named_query_result.ip)), named_query_results))
        named_query_result_extras: dict[str, NamedQueryResultExtra] = {}
        for named_query_result in named_query_results:
            if named_query_result.ip not in named_query_result_extras:
                named_query_result_extras[named_query_result.ip] = NamedQueryResultExtra(
                    named_query_result.ip, [named_query_result], search_ip_geolocation.search(named_query_result.ip))
            else:
                named_query_result_extras[named_query_result.ip].info.append(
                    named_query_result)
        results = [*named_query_result_extras.values()]
        logger.info(
            f'For {len(named_query_results)} matched logs, produced {len(results)} named_query_result_extras')
        return results

    def make_simple_report(self, named_query_result_extras: list[NamedQueryResultExtra]):
        records = list(map(lambda named_query_result_extra: RecordItem(named_query_result_extra.ip, len(
            named_query_result_extra.info), list(map(lambda info: info.datetime, named_query_result_extra.info)), named_query_result_extra.geolocation), named_query_result_extras))
        report = Report(self.filters[0].value, sum(map(lambda record: record.count, records)), records)
        return report


def _make_filters(filter_domain, fuzzy_search):
    # make filters
    filters = []
    filter = Filter('domain', filter_domain,
                    lambda key, value, match_dict: value in match_dict[key]
                    if fuzzy_search else
                    lambda key, value, match_dict: value == match_dict[key])
    filters.append(filter)
    return filters


def main(query_log_path=join(dirname(__file__), 'test.log'),
         dbPath=join(dirname(__file__), 'data', 'ip2region.xdb'),
         filter_domain='www.jwc.ynu.edu.cn',
         report_path=join(dirname(__file__), 'report.yaml'),
         sort_by: Literal['count', 'datetime']='count',
         fuzzy_search=False,):
    search_ip_geolocation = SearchIPGeolocation(dbPath)
    filters = _make_filters(filter_domain, fuzzy_search)
    named_query_log_parser = NamedQueryLogParser(query_log_path, filters)
    named_query_results = named_query_log_parser.parse()
    named_query_result_extras = named_query_log_parser.aggregate_by_source_ip(
        named_query_results, search_ip_geolocation)
    report = named_query_log_parser.make_simple_report(
        named_query_result_extras)
    if sort_by == 'count':
        report.sort_by_count()
    elif sort_by == 'datetime':
        report.sort_by_datetime()
    with open(report_path, 'w', encoding='utf-8') as yamlfile:
        # https://matthewpburruss.com/post/yaml/
        # convert the report object to dict then dump to yaml to avoid the yaml tag
        yaml.dump(report.to_dict(), yamlfile, sort_keys=False,
                  indent=2, allow_unicode=True)
        logger.info(f'write report: {report_path}')
    # with open(report_path, 'r', encoding='utf-8') as yamlfile:
    #     # https://matthewpburruss.com/post/yaml/
    #     loader = yaml.SafeLoader
    #     def report_loader(loader, node):
    #         return Report(**loader.construct_mapping(node, deep=True))

    #     def report_item_loadder(loader, node):
    #         return RecordItem(**loader.construct_mapping(node, deep=True))
    #     loader.add_constructor("!Report", report_loader)
    #     loader.add_constructor("!ReportItem", report_item_loadder)
    #     parsed_report = yaml.load(yamlfile, Loader=loader)
    #     logger.info(
    #         f'read report: {report_path}, parsed_report: {parsed_report}')


if __name__ == '__main__':
    fire.core.Display = lambda lines, out: print(*lines, file=out)
    fire.Fire(main)
