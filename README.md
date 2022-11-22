# iShare-JWT-Helper

Small tool for generating [iShare-compliant JWT](https://dev.ishareworks.org/introduction/jwt.html) to be used in iShare-environments.

## Config

The helper takes only two environment variables:

| Name | Description |
|------|-------------|
|I_SHARE_CLIENT_ID| ID of the client to get the token created for. Will be used as ```iss``` and ```sub``` and needs to match the cert/key.|
|I_SHARE_IDP_ID| ID of the participant to be connected with the token, f.e. another IDP. Will be used as ```aud```|

In addition, it expects the certificate and keyfiles under ```/certificates/certificate.pem``` and  ```/certificates/key.pem```. 

## Usage

The easiest way to use the tool is docker. Provide a config-file and the corresponding certificate and key. The config file is of form:

```yaml
EU.EORI.NLHAPPYPETS:
    certificate: "/happypets/certificate.pem"
    key: "/happypets/key.pem"
```

Execute the tool and provide the client and idp id to use from the config:

```shell
    docker run -v $(pwd)/example:/happypets -v $(pwd)/example/config.yaml:/config.yaml -e I_SHARE_CLIENT_ID="EU.EORI.NLHAPPYPETS" -e I_SHARE_IDP_ID="EU.EORI.NLPACKETDEL"  quay.io/wi_stefan/ishare-jwt-helper
```

This will create a token, using the test certificate and key in the [example-folder](./example/) for the client ```EU.EORI.NLHAPPYPETS``` and the intended participant ```EU.EORI.NLPACKETDEL```.

Result:

```
time="2022-06-22T07:01:49Z" level=info msg="CredentialsFolderPath: /certificates"
time="2022-06-22T07:01:49Z" level=info msg="Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlEOXpDQ0F0K2dBd0lCQWdJVVZVckZwOW5wZ1JGN1N5WTRlN05OWDU2aFl5NHdEUVlKS29aSWh2Y05BUUVMQlFBd2dZb3hDekFKQmdOVkJBWVRBa1JGTVE4d0RRWURWUVFJREFaQ1pYSnNhVzR4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVmTUIwR0ExVUVDZ3dXUmtsWFFWSkZJRVp2ZFc1a1lYUnBiMjRnWlM1V0xqRU1NQW9HQTFVRUN3d0RSR1YyTVNvd0tBWUpLb1pJaHZjTkFRa0JGaHRtYVhkaGNtVXRkR1ZqYUMxb1pXeHdRR1pwZDJGeVpTNXZjbWN3SGhjTk1qRXhNVEkwTVRJeE5USXhXaGNOTWpFeE1qSTBNVEl4TlRJeFdqQ0JpakVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVI4d0hRWURWUVFLREJaR1NWZEJVa1VnUm05MWJtUmhkR2x2YmlCbExsWXVNUXd3Q2dZRFZRUUxEQU5FWlhZeEtqQW9CZ2txaGtpRzl3MEJDUUVXRzJacGQyRnlaUzEwWldOb0xXaGxiSEJBWm1sM1lYSmxMbTl5WnpDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTFg5bWpYNjBjZDRUdVJzTVVCTWVZRVhMVXhsd2lXeEtreForcVNocW5ib1pZaFVlNEFMc1FSRDdvZ0xicjh1WXE4V2prMnFZM2M0WVZHRm4xaEdMZ2c2S2JkV0N6ZnVFbWFKN0pPTy9uQ3hkeGd0MkpvcXpkazhobFU4WUZaRlk0djNCMXZIb2h0TS9kTEU5VnNvTWNndWJPelArVmhkRXY1aExLUFJnR0FuS0IyaGhzN1ZXNERHeUM2QXBMZWRBU1Z3bzhob0NoTUM1cXFwRWhQWXlLdkpBWWJOV1Y5dndpLyswdXJ0cElNdkpocUNjR3ZHTi9TMUtiQlF5THFYakJBRnlSWFptMXBFYWFKTWxKTm00R1c2eUxLZUhhZFBlQndaUnpTR09kZFh4ZzFnaWlXcWtITGtZUUFnV0xXQVcyWEJFZ2VzTHlMa3FTNHNmVnhYb2NNQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZFNFF4SkU4WlhCWnM5V2NUcGlZZk1HK2psUjNNQjhHQTFVZEl3UVlNQmFBRkU0UXhKRThaWEJaczlXY1RwaVlmTUcramxSM01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCbmhkQ0YyTi9SYVFRc0RGMGx6aGlFdkJDa010eWQyVnNOR0ZBcnlXVXl1akpSYlhCQ1hxNkMzdW1jQy9qSHJpd3VIc0JZSkZsSk04VGI4bmVhTTJRRlhRdGxFb0ozVDNuMndVSzArUk1zcUFlb2dRdFFsVVZZMU5ndktlb0pHdXBmQm9qRUxrQU9IWXFNZVhQT0NITjN3cEhZWkYwUWZOMXowYWlxV1FCZ3h1V3A3M2ErQUs3SDg2UEpJOGVleTNib0cwR3lEdG9QVndXNWJSZ0hlbzU5NUVGRHBTZWRJcmQ5ckhWY3F3RUdZRmpoNUZsYmJLQkVqTkRVVjRKbFp1L0pwTWErK0RuUERkOTBFRldaR0tzWnBpM0FMbXlhL2w5RHBFU1NNV1hXZTlaQ1M3cjZ2SGZMQldsNThvcmpYdUtySXRtZ3BZRXZHbVZPKzJ4WkJ1RWc9Il19.eyJhdWQiOiJFVS5FT1JJLk5MUEFDS0VUREVMIiwiZXhwIjoxNjU1ODgxMzM5LCJpYXQiOjE2NTU4ODEzMDksImlzcyI6IkVVLkVPUkkuTkxIQVBQWVBFVFMiLCJqdGkiOiI0MWU5OWE0OC05Mjc4LTRjMjYtOTM3ZC1iYTAxYTQ0OWFiNWUiLCJzdWIiOiJFVS5FT1JJLk5MSEFQUFlQRVRTIn0.ExdTEUp20_5a-M0yu4EQd0dZDhu4u5HCYCQQIb0JwSc6jUrSxgcTu2lTCDA5ct-M9oCBWBSOI2EPR-0DPzzQftZC-7YD_BmAsCnXOzUbR7nKSYrCzM7CwngwhriVLc_pVfzineyG90UsHmPlV1P9n785zEukNzuZLfNyqxtT_z1zfNLl0bg4dc9yz9euLv3zdvOXDsMOI21UPgu3qcGhr0rNStK7Og8AzodHdCZoDyctzKMjiGRIMQzAdmXFIqbx3QAjlQPN0pyG_-3OM8_I685BhCYXvT6ATw-D9HJmWlbyxADccs112S38_LVnOc_DoUBVeYZTFVQAjgwEmIXb9g"
```
Copy the token and use it. Be aware that its only valid for 30s, due to [the specifcation of iShare](https://dev.ishareworks.org/introduction/jwt.html#jwt-payload).

## Run as server

When the environment variable ```RUN_SERVER``` is set to ```true```, the tool can run as a service. Tokens can be requested with the clientId(has to be configured in the config-file) and the idpId as the the audience of the token. ```/token?clientId=EU.EORI.NLHAPPYPETS&idpId=EU.EORI.NLPACKETDEL```. 

```shell 
    docker run -v $(pwd)/example:/happypets -v $(pwd)/example/config.yaml:/config.yaml -e RUN_SERVER="true" -p 8080:8080 quay.io/wi_stefan/ishare-jwt-helper
```

Get the token: 

```shell
    curl --location --request GET 'localhost:8080/token?clientId=EU.EORI.NLHAPPYPETS&idpId=EU.EORI.NLPACKETDEL' \
```
Response: 
```json
{
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlEOXpDQ0F0K2dBd0lCQWdJVVZVckZwOW5wZ1JGN1N5WTRlN05OWDU2aFl5NHdEUVlKS29aSWh2Y05BUUVMQlFBd2dZb3hDekFKQmdOVkJBWVRBa1JGTVE4d0RRWURWUVFJREFaQ1pYSnNhVzR4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVmTUIwR0ExVUVDZ3dXUmtsWFFWSkZJRVp2ZFc1a1lYUnBiMjRnWlM1V0xqRU1NQW9HQTFVRUN3d0RSR1YyTVNvd0tBWUpLb1pJaHZjTkFRa0JGaHRtYVhkaGNtVXRkR1ZqYUMxb1pXeHdRR1pwZDJGeVpTNXZjbWN3SGhjTk1qRXhNVEkwTVRJeE5USXhXaGNOTWpFeE1qSTBNVEl4TlRJeFdqQ0JpakVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVI4d0hRWURWUVFLREJaR1NWZEJVa1VnUm05MWJtUmhkR2x2YmlCbExsWXVNUXd3Q2dZRFZRUUxEQU5FWlhZeEtqQW9CZ2txaGtpRzl3MEJDUUVXRzJacGQyRnlaUzEwWldOb0xXaGxiSEJBWm1sM1lYSmxMbTl5WnpDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTFg5bWpYNjBjZDRUdVJzTVVCTWVZRVhMVXhsd2lXeEtreForcVNocW5ib1pZaFVlNEFMc1FSRDdvZ0xicjh1WXE4V2prMnFZM2M0WVZHRm4xaEdMZ2c2S2JkV0N6ZnVFbWFKN0pPTy9uQ3hkeGd0MkpvcXpkazhobFU4WUZaRlk0djNCMXZIb2h0TS9kTEU5VnNvTWNndWJPelArVmhkRXY1aExLUFJnR0FuS0IyaGhzN1ZXNERHeUM2QXBMZWRBU1Z3bzhob0NoTUM1cXFwRWhQWXlLdkpBWWJOV1Y5dndpLyswdXJ0cElNdkpocUNjR3ZHTi9TMUtiQlF5THFYakJBRnlSWFptMXBFYWFKTWxKTm00R1c2eUxLZUhhZFBlQndaUnpTR09kZFh4ZzFnaWlXcWtITGtZUUFnV0xXQVcyWEJFZ2VzTHlMa3FTNHNmVnhYb2NNQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZFNFF4SkU4WlhCWnM5V2NUcGlZZk1HK2psUjNNQjhHQTFVZEl3UVlNQmFBRkU0UXhKRThaWEJaczlXY1RwaVlmTUcramxSM01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCbmhkQ0YyTi9SYVFRc0RGMGx6aGlFdkJDa010eWQyVnNOR0ZBcnlXVXl1akpSYlhCQ1hxNkMzdW1jQy9qSHJpd3VIc0JZSkZsSk04VGI4bmVhTTJRRlhRdGxFb0ozVDNuMndVSzArUk1zcUFlb2dRdFFsVVZZMU5ndktlb0pHdXBmQm9qRUxrQU9IWXFNZVhQT0NITjN3cEhZWkYwUWZOMXowYWlxV1FCZ3h1V3A3M2ErQUs3SDg2UEpJOGVleTNib0cwR3lEdG9QVndXNWJSZ0hlbzU5NUVGRHBTZWRJcmQ5ckhWY3F3RUdZRmpoNUZsYmJLQkVqTkRVVjRKbFp1L0pwTWErK0RuUERkOTBFRldaR0tzWnBpM0FMbXlhL2w5RHBFU1NNV1hXZTlaQ1M3cjZ2SGZMQldsNThvcmpYdUtySXRtZ3BZRXZHbVZPKzJ4WkJ1RWc9Il19.eyJhdWQiOiJFVS5FT1JJLk5MUEFDS0VUREVMIiwiZXhwIjoxNjY5MTAxMDk5LCJpYXQiOjE2NjkxMDEwNjksImlzcyI6IkVVLkVPUkkuTkxIQVBQWVBFVFMiLCJqdGkiOiJjODAzNWZlMi0xODI4LTQ4YzUtYTU3Yi04OGFiMTdmYTI5OGMiLCJzdWIiOiJFVS5FT1JJLk5MSEFQUFlQRVRTIn0.MbCdMRzoRPZNQrwtwQdFws5E40JWaCglG8ozblXwpUD2Wt3PWAshDEU7gkiTtoTkWSYnpmnfFo4a4fT9DbsWycM-xRR0BKH3pcIPawDVJsag9mk91Q9nGcYXjK54-kUx0nKrko0P7BUhjE5IVrjXtnQxLqGJo-_M7SfFsBxegDRiBu9qB8bTIBENNSMCq_gvcOjeGR0hlRvXlFz4vDxLMHRxadiY9NGfX3duNKKW1dx1vlHx4n0LJ2RwgafMIBLjYmeuSYMb64WoHDMaEff6Yg1H-c_eyGosjeEmLmIBW9ADCC8rMXz0ySq5StdKTIyo92sLrlj5oBREiuGGrHEy7A"
}
```