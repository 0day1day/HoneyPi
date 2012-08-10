#!/usr/bin/env python
from optparse import OptionParser
import hashlib, os, urllib, urllib2, json, httplib, mimetypes, time, magic
import peinfos, yaraScan
from datetime import date
from cymru.mhr.dns import DNSClient as mhr


# {{{ http://code.activestate.com/recipes/146306/ (r1)

def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
# end of http://code.activestate.com/recipes/146306/ }}}


def calculateHash(file_path):
  """docstring for calculateHash"""
  if os.path.isfile(file_path):
    file_content = open(file_path, 'rb')
    return hashlib.sha256(file_content.read()).hexdigest()

def teamCymruCheck(file_path):
  """docstring for teamCymruCheck"""
  client = mhr()
  h = hashlib.sha1(file(file_path, 'r').read()).hexdigest()
  return client.lookup(h)


class VirusTotalUploader:
  def __init__(self, path, recursive, yes, days):
    """docstring for __init__"""
    self.apikey = '49d1e84afff18f626f23f2d39be0a8f718b0ed644a9577e488ade7f7cd6916b5'
    self.url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
    self.url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
    self.av_list = ['Avast', 'ClamAV', 'F-Secure', 'Kaspersky', 'Microsoft']
    self.path = path
    if os.path.isdir(path):
      self.recursive = recursive
    else:
      self.recursive = False
    self.yes = yes
    self.days = days
    self.curr_timestamp = time.time()

  def check_report(self, file_path):
      """Check if a report for a binary exists on VirusTotal"""
    #if os.path.isfile(file_path):
      print "Check report on VT for file : %s" % file_path
      file_hash = calculateHash(file_path)
      print "Sha256 : %s" % file_hash 
      # Prepare HTTP request
      parameters = {'resource' : file_hash,
          'apikey' : self.apikey}
      data = urllib.urlencode(parameters)
      req = urllib2.Request(self.url_report, data)
      # Send request
      response = urllib2.urlopen(req)
      json_res = json.loads(response.read())
      # Show results
      #print 'RESPONSE CODE', json_res['response_code']
      if json_res['response_code'] == 1:
        print "File type : %s" % (magic.from_file(file_path)) #Can fail with some version of magic module
        print """
  VIRUSTOTAL :
  ------------
  Scan date %s
  Detection rate : %d/%d
  Report URL : %s
"""  % (json_res['scan_date'], json_res['positives'], json_res['total'], json_res['permalink'])
        print "  AV result summary :"
        for av in self.av_list:
          try:
            print "    %s : %s" % (av, json_res['scans'][av]['result'])
          except KeyError, e:
            print "    %s : No results" % (av)


        # TeamCymru infos : Detection rate / timestamp
        cymru = teamCymruCheck(file_path)
        if cymru.ts is not None:
          print """
  TeamCymru :
  -----------
  Detection rate : %s%%
  Date : %s
""" % (cymru.detection, date.fromtimestamp(long(cymru.ts)).strftime('%d/%m/%Y'))

        #Yara
        yara = yaraScan.YaraScan(file_path)
        yara.scan_file()
        yara.format()


        #PE infos
        pe = peinfos.PeInfos(file_path)
        pe.execute()

      
        print '-'*80, '\n'*5
      else:
        print '  |-> ', json_res['verbose_msg']
      return json_res['response_code']
    #else:
    #  print "/!\\ %s is not a file or doesn't exist !" % file_path
  
  def scan_binary(self, file_path):
    """Scan a binary on VirusTotal"""
    print "Scanning file %s" % file_path
    parameters = [('apikey', self.apikey)]
    file_content = open(file_path, 'rb').read()
    file_to_upload = [("file", os.path.basename(file_path), file_content)]
    json_res = json.loads(post_multipart('www.virustotal.com', self.url_scan, parameters, file_to_upload))
    #print repr(json_data)

    if json_res['response_code'] != 1:
      print '  |-> ', json_res['verbose_msg']
    else:
      print '  |-> Upload OK'
      print '  |-> Permalink : %s' % json_res['permalink']
    return json_res['response_code']

  def blah(self, file_path):
    """docstring for blah"""
    if self.days != 0:
      file_timestamp = os.path.getmtime(file_path)
      if ((self.curr_timestamp - file_timestamp) <= (3600*24*self.days)):
        # check file if it has less than X days
        check_file = True
      else:
        # file too old, don't check
        check_file = False
    else:
      # don't look file's date, and check file
      check_file = True

    if check_file:
      do_scan = self.yes
      if (self.check_report(file_path) == 0):
        if not self.yes:
          res = None
          while res not in ['y', 'Y', 'n', 'N', '']:
            res = raw_input("Do you want to upload file %s to VirusTotal ? [y/n] " % file_path)
          if res.lower() == 'y':
            do_scan = True
        
        if do_scan:
          self.scan_binary(file_path)
          time.sleep(30)
          self.check_report(file_path)
      time.sleep(30)

  def execute(self):
    """docstring for execute"""
    if os.path.isfile(self.path):
      self.blah(self.path)
    elif os.path.isdir(self.path):
      for root, dirs, files in os.walk(self.path):
        for f in files:
          self.blah(os.path.join(root, f))
        if not self.recursive:
          break


if __name__ == "__main__":
  usage = "usage: %prog [options] [file|directory]"
  parser = OptionParser(usage=usage)
  parser.add_option('-r', '--recursive', dest='recursive', action='store_true', default=False, help='Check and/or Upload binairies in all sub-directories')
  parser.add_option('-y', '--yes', dest='yes', action='store_true', default=False, help='Upload all binairies to VirusTotal whithout ask to user')
  parser.add_option('-d', '--days', dest='days', type='int', default=0, help='Check file if it is younger than X days')
  (option, args) = parser.parse_args()
  if len(args) == 0:
    parser.print_help()
    exit()
  vt = VirusTotalUploader(args[0], option.recursive, option.yes, option.days)
  vt.execute()
