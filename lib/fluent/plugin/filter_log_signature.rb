#
# Copyright 2023- wang.zhe
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "fluent/plugin/filter"
require 'openssl'
require 'net/http'
require 'uri'
require 'json'
require 'base64'

module Fluent
  module Plugin
    class LogSignatureFilter < Fluent::Plugin::Filter
      Fluent::Plugin.register_filter("log_signature", self)

      config_param :keys, :array, value_type: :string
      config_param :delimiter, :string, default: '&'
      config_param :des_url, :string
      config_param :secret_name, :string, default: ''
      config_param :auth, :string, default: ''
      config_param :sign_log_print, :bool, default: false
      config_param :version_prefix, :string, default: ''
      
      def configure(conf)
        super

        if @keys.empty?
          raise Fluent::ConfigError, 'No keys specified for concatenation'
        else
          @keys.sort!
        end

        @cache = {}

        retries = 0
        max_retries = 3
        loop do
          secret = get_secret(@des_url, @secret_name)
          break if secret
          retries += 1
          if retries <= max_retries
            wait = 2 ** retries
            log.warn "Failed to fetch secret on startup, retry #{retries}/#{max_retries} in #{wait}s..."
            sleep wait
          else
            log.error "Failed to fetch secret after #{max_retries} retries on startup"
            break
          end
        end
      end

      def filter(tag, time, record)
        concat_values = @keys.map { |key| record.fetch(key, "") }.join(@delimiter)
        if @sign_log_print
          log.info "Concatenated values: #{concat_values}"
        end
        secret = get_secret(@des_url, @secret_name)
        unless secret
          log.error "Failed to obtain secret, skipping signature for this record"
          return record
        end
        signature = hmac_signature(concat_values, secret)
        record['signature'] = @version_prefix.empty? ? signature : "#{@version_prefix}-#{signature}"
        if @sign_log_print
          log.info "Signature result is #{record['signature']}"
        end
        record
      end

      def hmac_signature(concat_values, secret)
        hmac = OpenSSL::HMAC.new(secret, OpenSSL::Digest.new('sm3'))
        hmac.update(concat_values)
        hmac.hexdigest
      end

      def get_secret(url, secret_name)
        return @cache['secret'] if @cache.key?('secret')

        log.info "get secret from des svc"
        url = URI(url)
        http = Net::HTTP.new(url.host, url.port)
        http.open_timeout = 5
        http.read_timeout = 10
        request = Net::HTTP::Post.new(url)
        request["Content-Type"] = "application/json"
        request["Authorization"] = Base64.decode64(@auth)
        request.body = JSON.dump({ "SecretName": secret_name })
        begin
          response = http.request(request)
          if response.code == '200'
            parse = JSON.parse(response.body)
            secret = parse['Result']['SecretPlaintext']
            @cache['secret'] = secret
            return secret
          else
            log.error "get secret from des failed"
          end
        rescue => e
          log.error "Error: #{e.message}"
        end
      end
    end
  end
end