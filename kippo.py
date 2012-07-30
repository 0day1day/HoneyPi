#!/usr/bin/env python
import sys, json, glob, os, pygeoip, playlog, magic
from datetime import date

class Kippo():
  def __init__(self, path, geoip_file):
    """docstring for __init__"""
    self.path = path
    self.log_file = None
    self.stats = dict()
    self.stats['ip'] = dict()
    self.stats['country'] = dict()
    self.stats['login'] = dict()
    self.stats['pwd'] = dict()
    self.stats['auth'] = dict()
    self.curr_date = date.today().strftime('%Y%m%d') #ex : 20120123
    
    self.geoip_file = None
    try:
      self.geoip_file = pygeoip.GeoIP(geoip_file, pygeoip.MEMORY_CACHE)
    except e:
      print 'ERROR %s' % e

  def load_json_file(self):
    """docstring for load_json_file"""
    try:
      self.log_file = open(os.path.join(self.path, 'log/HoneyPi.log'), 'r')
      line = self.log_file.readline()
      while line:
        # init temp variables
        #print repr(line), line
        try:
          #ip, login, pwd, success = line.split(',')
          json_data = json.loads(line)
          #categories = {'ip' : ip, 'login' : login, 'pwd' : pwd, 'success' : success}
  
          # push infos in dict() variable
          for k,v in json_data.items():
            # Check Country from IP
            if k == 'ip' and (self.geoip_file is not None):
              country = self.geoip_file.country_name_by_addr(v)
              if country  not in self.stats['country'].keys():
                self.stats['country'][country] = 1
              else:
                self.stats['country'][country] += 1

            # ip, login, pwd and success stats
            if v not in self.stats[k].keys():
              self.stats[k][v] = 1
            else:
              self.stats[k][v] += 1
        except ValueError, e:
          print 'ERROR : %s' % e
        line = self.log_file.readline()
      self.log_file.close()
    except Exception, e:
      print 'ERROR : %s' % e


  def play_tty(self):
    """docstring for play_tty"""
    # Based on playlog.py (from kippo)
    tty_files = glob.glob('%s-*' % (os.path.join(self.path, 'log/tty', self.curr_date)))
    playlog_settings = {'tail': 0,
                        'maxdelay': 3.0,
                        'input_only': 0,
                        'both_dirs': 1,
                        'outfile': ''}
    print '\n\n', '#'*10, 'TTY', '#'*10, '\n'
    for tty in tty_files:
      try:
        f = open(tty, 'rb')
      except Exception, e:
        print 'ERROR : %s' % (e)
      else:
        playlog.playlog(f, 0, playlog_settings)
        f.close()
      finally:
        print '\n\n', '-'*10, '\n'

  def downloaded_files(self):
    """docstring for downloaded_files"""
    dl_files = glob.glob('%s*' % (os.path.join(self.path, 'dl', self.curr_date)))
    print '\n\n', '#'*10, 'DOWNLOADS', '#'*10, '\n'
    for dl in dl_files:
      try:
        print '%s : %s' % (os.path.basename(dl), magic.from_file(dl)) # Can fail with some magic module versions ...
      except Exception, e:
        print 'ERROR : %s' % e

  def topN(self, n=10):
    """docstring for topN"""
    print '#'*10, 'TOP %i' % (n), '#'*10
    for category, data in self.stats.items():
      print '\n', '-'*5, category, '-'*5
      tmp = sorted(data.iteritems(), key=lambda (k,v): (v,k), reverse=True)
      if category == 'ip' and (self.geoip_file is not None):
        for key, value in tmp[:n]:
          print '%s [%s] : %s' % (key, self.geoip_file.country_code_by_addr(key), value)

      else:  
        for key, value in tmp[:n]:
          print '%s : %s' % (key,value)

  def execute(self, n=10):
    """docstring for execute"""
    self.load_json_file()
    self.topN(n)
    self.play_tty()
    self.downloaded_files()
    


if __name__ == '__main__':
  if len(sys.argv) > 1:
    k = Kippo(sys.argv[1], sys.argv[2])
    k.execute()
  else:
    print '%s need path to HoneyPi.log and GeoIp.dat files as argument' % sys.argv[0]
