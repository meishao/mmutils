# mmutils
Tools for working with MaxMind GeoIP csv and dat files

実行方法：
python <変換プログラム> <脅威IPアドレスリスト> <脅威種別>

実行例：
# python cti.py malicious_ips-Jun_26_2017.csv malware

出力：
cti_output.csv - 中間変換データ
cti.dat - maxmindデータベース用

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
