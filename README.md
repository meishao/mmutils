# mmutils
Tools for working with MaxMind GeoIP csv and dat files

環境配置：
```
git clone https://github.com/mteodoro/mmutils.git
cd mmutils
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

実行方法：
python <変換プログラム> <脅威IPアドレスリスト> <脅威種別>

実行例：
```
# python cti.py malicious_ips-Jun_26_2017.csv malware
```

出力：
cti_output.csv - 中間変換データ
cti.dat - maxmindデータベース用

データ確認：
```
$ ipython
WARNING: Attempting to work in a virtualenv. If you encounter problems, please install IPython inside the virtualenv.
Python 2.7.10 (default, Jul 14 2015, 19:46:27) 
Type "copyright", "credits" or "license" for more information.

IPython 3.0.0 -- An enhanced Interactive Python.
?         -> Introduction and overview of IPython's features.
%quickref -> Quick reference.
help      -> Python's own help system.
object?   -> Details about 'object', use 'object??' for extra details.

In [1]: import pygeoip

In [2]: geo = pygeoip.GeoIP('cti.dat')

In [3]: print json.dumps(geo.record_by_addr('10.0.0.1'), indent=4, sort_keys=True)
{
    "area_code": 650, 
    "city": "Redwood City", 
    "continent": "NA", 
    "country_code": "US", 
    "country_code3": "USA", 
    "country_name": "United States", 
    "dma_code": 807, 
    "latitude": 37.4914, 
    "longitude": -122.211, 
    "metro_code": "San Francisco, CA", 
    "postal_code": "94063", 
    "region_code": "CA", 
    "time_zone": "America/Los_Angeles"
}
```

Fluentdと連携使用方法：

apache例：
```
<source>
  @type tail
  path /var/log/httpd/access_log
  tag geo.access
  format apache2
  #message_key message
</source>

#<filter vm.access.**>
#  @type record_transformer
#  <record>
#    tag vm.access.${record["host"]}
#  </record>
#</filter>

<match geo.access>
  @type geoip
  geoip_lookup_key host
  geoip_database "/opt/td-agent/embedded/lib/ruby/gems/2.1.0/gems/fluent-plugin-geoip-0.7.0/data/cti.dat"
  
  <record> 
    cti_type ${city['host']}
  </record>
 
  remove_tag_prefix geo.
  add_tag_prefix ip.
  skip_adding_null_record false
</match>

<match ip.access>
  @type geoip
  geoip_lookup_key host
  geoip_database "/opt/td-agent/embedded/lib/ruby/gems/2.1.0/gems/fluent-plugin-geoip-0.7.0/data/GeoLiteCity.dat"
  <record>
    cti_country ${country_name['host']}
    cti_city ${city['host']}
  </record>

  remove_tag_prefix ip.
  add_tag_prefix vm.
  skip_adding_null_record false
</match>

<match vm.access>
#  @type file
#  path /var/log/td-agent/access/vm.access
  @type stdout
</match>
```
