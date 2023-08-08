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

module Fluent
  module Plugin
    class LogSignatureFilter < Fluent::Plugin::Filter
      Fluent::Plugin.register_filter("log_signature", self)

      config_param :keys, :array, value_type: :string
      config_param :delimiter, :string, default: '&'
      def configure(conf)
        super

        if @keys.empty?
          raise Fluent::ConfigError, 'No keys specified for concatenation'
        else
          @keys.sort!
        end
      end
      def filter(tag, time, record)
        concat_values = @keys.map { |key| record[key] }.compact.join(@delimiter)
        log.info "Concatenated values: #{concat_values}"
        record['signature'] = hmac_signature(concat_values, record['secret'])
      end
      def hmac_signature(concat_values, secret)
        hmac = OpenSSL::HMAC.new(secret,OpenSSL::Digest.new('sm3'))
        hmac.update(concat_values)
        hmac.hexdigest
      end
    end
  end
end
