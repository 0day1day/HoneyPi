#!/usr/bin/env python

import pefile, string, sys

class PeInfos:
  """
  http://code.google.com/p/pefile/wiki/UsageExamples
  http://code.google.com/p/pefile/wiki/PEiDSignatures
  """

  def __init__(self, file_path):
    """docstring for __init__"""
    self.path = file_path
    try:
      self.file = pefile.PE(file_path)
    except:
      self.file = None

  def generic_infos(self):
    """docstring for generic_infos"""
    if self.file.is_exe():
      print 'EXE file'
    elif self.file.is_dll():
      print 'DLL file'
    elif self.file.is_driver():
      print 'DRIVER file'
    print """
Address Of Entry Point : %s
ImageBase : %s\n""" % (hex(self.file.OPTIONAL_HEADER.AddressOfEntryPoint), hex(self.file.OPTIONAL_HEADER.ImageBase))
    try:
      for fileinfo in self.file.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
          for st in fileinfo.StringTable:
            for entry in st.entries.items():
              print '%s: %s' % (entry[0], entry[1])

        if fileinfo.Key == 'VarFileInfo':
          for var in fileinfo.Var:
            print '%s: %s' % var.entry.items()[0]
    except Exception, e:
      print 'ERROR : Fail to get file\'s informations (%s)' % (e)

  def sections(self):
    """docstring for sections"""
    print "\n\n- Sections -"
    for section in self.file.sections:
      entropy = section.get_entropy()
      output = filter(lambda x: x in string.printable, section.Name)
      output += "\tEntropy : %f" % entropy
      if ((entropy > 0 and entropy < 1) or entropy > 7):
        output += " [SUSPICIOUS]"
      print output

  def imports(self):
    print "\n\n- Imports -"
    """docstring for imports"""
    try:
      for entry in self.file.DIRECTORY_ENTRY_IMPORT:
        print entry.dll
        for imp in entry.imports:
          print '\t', hex(imp.address), imp.name
    except Exception, e:
      print 'ERROR : Fail to get Imports (%s)' % (e)

  def exports(self):
    print "\n\n- Exports -"
    """docstring for exports"""
    try:
      for exp in self.file.DIRECTORY_ENTRY_EXPORT.symbols:
        print hex(self.file.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
    except Exception, e:
      print 'ERROR : Fail to get Exports (%s)' % (e)

  def execute(self):
    """docstring for execute"""
    if self.file is not None:
      self.generic_infos()
      self.sections()
      self.imports()
      self.exports()

if __name__ == '__main__':
  if len(sys.argv) > 1:
    pe = PeInfos(sys.argv[1])
    pe.execute()
  else:
    print '%s need file\'s path to scan' % sys.argv[0]
