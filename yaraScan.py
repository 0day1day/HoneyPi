#!/usr/bin/env python
import yara, sys


class YaraScan:
  
  def __init__(self, file_to_scan):
    """docstring for __init__ """
    self.rules_files = {'Activities' : 'yara/capabilities.yara', 'File type' : 'yara/magic.yara', 'packer' : 'yara/packer.yara'}
    self.file_to_scan = file_to_scan
    self.file_content = open(file_to_scan, 'rb').read()
    self.results = []

  def scan_file(self):
    """docstring for scan_file"""
    rules = yara.compile(filepaths=self.rules_files)
    matches = rules.match(data=self.file_content)
    for m in matches:
      self.results.append(m.rule)

  def format(self):
    """docstring for format"""
    print 'Yara infos :'
    for i in self.results:
      print '\t%s' % (i)

if __name__ == '__main__':
  if len(sys.argv) > 1:
    y = YaraScan(sys.argv[1])
    y.scan_file()
    y.format()
  else:
    print '%s need file\'s path to scan' % sys.argv[0]
