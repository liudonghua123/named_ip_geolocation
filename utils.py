import time
from halo import Halo
import logging
import sys
import os
import gzip
from os.path import dirname, join, realpath, basename

# config logging for both stdout and file
level=os.environ.get("LOG_LEVEL", "INFO")

def init_logging(file_name=join(dirname(realpath(__file__)), "app.log"), level=level):
    logging.basicConfig(
        format="%(levelname)s %(asctime)s - %(message)s",
        level=level,
        handlers=[logging.FileHandler(file_name), logging.StreamHandler(sys.stdout)],
    )
    logger = logging.getLogger(basename(file_name))
    return logger


class spinner_context:
    def __init__(self, start_text: str, end_text: str = None, spinner_indicator: str = 'dots'):
        self.start_text = start_text
        self.end_text = end_text or start_text
        self.spinner_indicator = spinner_indicator
        self.spinner = Halo(text=self.start_text, spinner=self.spinner_indicator)
        self.start_time = None
    def __enter__(self):
        self.start_time = time.perf_counter()
        self.spinner.start()
        return self.spinner
    def __exit__(self, exc_type, exc_value, traceback):
        self.spinner.succeed(f'{self.end_text}, took {time.perf_counter() - self.start_time:.2f}s')

def get_file_line_count(file_path):
    open_fn = gzip.open if file_path.endswith('.gz') else open 
    with open_fn(file_path, mode='rb') as fp:
        def _read(reader):
            buffer_size = 1024 * 1024
            b = reader(buffer_size)
            while b:
                yield b
                b = reader(buffer_size)
        content_generator = _read(fp.read)
        count = sum(buffer.count(b'\n') for buffer in content_generator)
        return count