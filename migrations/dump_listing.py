#!/usr/bin/env python

import re

from os import path
from os import listdir
from typing import Iterable, Tuple
from typing import Optional
from dataclasses import dataclass


version_directory = path.join(path.dirname(__file__), 'versions')


@dataclass
class Version:
    filename      :str
    revision      :str
    short_message :str
    long_message  :str
    down_revision :Optional[str]

    def __hash__(self):
        return int(self.revision, 16)

    def __eq__(self, othr :'Version'):
        return (self.revision == othr.revision)


down_revision_pattern :re.Pattern = re.compile(r"down_revision = '(?P<down_revision>[0-9a-f]*)'")


def get_revision_and_short_message_from_filename(filename :str) -> Tuple[str, str]:
    without_extension = filename.rsplit('.', 1)[0]
    revision, short_message = without_extension.split('_', 1)
    short_message = short_message.replace('_', ' ')
    return revision, short_message


def get_down_revision_from_content(content :str) -> str:
    down_revision_match = re.search(down_revision_pattern, content)
    if down_revision_match:
        return down_revision_match.group('down_revision')
    else:
        return None


def get_long_message_and_down_revision_from_filename(filename :str) -> Tuple[str, str]:
    fullname = path.join(version_directory, filename)
    with open(fullname, mode='rt') as handle:
        long_message = handle.readline().lstrip('"').rstrip()
        down_revision = get_down_revision_from_content(handle.read())
    return long_message, down_revision


def order_versions(versions :Iterable[Version]) -> Iterable[Version]:
    # find the start
    version = next(filter(lambda x: x.down_revision is None, versions))
    # continue until the next revision cannot be found
    poison_pill = None
    while version:
        yield version
        version = next(
            filter(lambda x: x.down_revision == version.revision, versions),
            poison_pill
        )


versions = {
    Version(
        filename,
        *get_revision_and_short_message_from_filename(filename),
        *get_long_message_and_down_revision_from_filename(filename)
    ) for filename in listdir(version_directory)
}


print(
    *map(
        lambda x: f'{x.revision}: {x.long_message}',
        order_versions(versions)
    ),
    sep='\n',
    end='\n\n',
)