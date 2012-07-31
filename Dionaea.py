#!/usr/bin/env python
import sys, sqlite3, pygeoip

class Dionaea:
  def __init__(self, sqlite_file, geoip_file):
    """docstring for __init__"""
    self.sqlite_file = sqlite_file
    self.conn = sqlite3.connect(sqlite_file)
    self.conn.row_factory = sqlite3.Row
    self.cur = self.conn.cursor()
    self.geoip_file = None
    try:
      self.geoip_file = pygeoip.GeoIP(geoip_file, pygeoip.MEMORY_CACHE)
    except IOError, e:
      print 'ERROR %s' % e
    #TODO ajouter la gestion des timestamp pour avoir les stats des X derniers jours

  def downloads(self, n=10):
    """docstring for downloads"""
    downloads = dict()
    #XXX lier l'URL (IP) a un pays
    req = "select download_url, download_md5_hash, count() as number from downloads group by download_url order by number desc limit ?"
    self.cur.execute(req, (n,))
    line = self.cur.fetchone()
    print '\n\nDOWNLOADS'
    while line: 
      print '%s : %d' % (line['download_url'], line['number'])
      line = self.cur.fetchone()

  def db_logins(self, n=10):
    """docstring for db_logins"""
    stats = dict()
    stats['logins'] = dict()
    stats['password'] = dict()
    stats['service'] = dict()
    stats['ip'] = dict()
    stats['hostname'] = dict()
    stats['countries'] = dict()

    req = "select * from logins, connections where logins.connection = connections.connection"
    self.cur.execute(req)
    line = self.cur.fetchone() 
    keys = {'login_username': stats['logins'],
            'login_password': stats['password'],
            'connection_protocol': stats['service'],
            'remote_host': stats['ip'],
            'remote_hostname': stats['hostname']
         }
    while line:
      for k,v in keys.items():
        if line[k] not in v.keys():
          v[line[k]] = 1
        else:
          v[line[k]] += 1
        if k == 'remote_host':
          country = self.geoip_file.country_code_by_addr(line[k])
          if country not in stats['countries'].keys():
            stats['countries'][country] = 1
          else:
            stats['countries'][country] += 1
      line = self.cur.fetchone()

    print '\n\nDATABASE LOGINS'
    for category, data in stats.items():
      print '-'*5, category, '-'*5
      tmp = sorted(data.iteritems(), key=lambda (k,v): (v,k), reverse=True)
      if category == 'ip' and (self.geoip_file is not None):
        for key, value in tmp[:n]:
          print '%s [%s / %s] : %s' % (key, self.geoip_file.country_code_by_addr(key), self.geoip_file.country_name_by_addr(key), value)
      else:  
        for key, value in tmp[:n]:
          print '%s : %s' % (key,value)
  
  def connection_stats(self, n=10):
    """docstring for connection_stats"""
    req = "select connection_protocol, count() as number from connections group by connection_protocol order by number desc limit ?"
    self.cur.execute(req, (n,))
    line = self.cur.fetchone()
    print '\n\nCONNECTION PROTOCOL'
    while line: 
      print '%s : %d' % (line['connection_protocol'], line['number'])
      line = self.cur.fetchone()

    req = "select remote_host, count() as number from connections group by remote_host order by number desc limit ?"
    self.cur.execute(req, (n,))
    line = self.cur.fetchone()
    print '\n\nCONNECTION REMOTE HOST'
    while line: 
      if self.geoip_file:
        print '%s [%s / %s] : %d' % (line['remote_host'], self.geoip_file.country_code_by_addr(line['remote_host']), self.geoip_file.country_name_by_addr(line['remote_host']), line['number'])
      else:
        print '%s : %d' % (line['remote_host'], line['number'])
      line = self.cur.fetchone()

  def mssql(self, n=10):
    """docstring for mssql"""
    req = "select mssql_command_cmd, count() as number from mssql_commands group by mssql_command_cmd order by number desc limit ?"
    self.cur.execute(req, (n,))
    line = self.cur.fetchone()
    print '\n\nMSSQL COMMANDS'
    while line: 
      print '%s : %d\n' % (line['mssql_command_cmd'], line['number'])
      line = self.cur.fetchone()

  def mysql(self, n=10):
    """docstring for mysql"""
    req = "select mysql_command_arg_data, count() as number from mysql_command_args group by mysql_command_arg_data order by number desc limit ?"
    self.cur.execute(req, (n,))
    line = self.cur.fetchone()
    print '\n\nMYSQL COMMANDS'
    while line: 
      print '%s : %d\n' % (line['mysql_command_arg_data'], line['number'])
      line = self.cur.fetchone()

  def execute(self, n=10):
    """docstring for execute"""
    self.connection_stats()
    self.downloads()
    self.db_logins()
    self.mysql()
    self.mssql()


if __name__ == '__main__':
  if len(sys.argv) > 1:
    k = Dionaea(sys.argv[1], sys.argv[2])
    k.execute()
  else:
    print '%s need path to logsql.sqlite and geoip file' % sys.argv[0]
