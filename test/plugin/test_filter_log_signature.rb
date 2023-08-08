require 'helper'
require 'test/unit'
require 'fluent/log'
require 'fluent/test'

require "fluent/plugin/filter_log_signature.rb"

class LogSignatureFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  CONFIG = %!
    keys timestamp,message
    delimiter &
    des_url http://10.255.88.173:30379/desGetSecret
    secret_name test
    auth QmFzaWMgWTJ4ekxYTnBaMjVsY2pwemRHRmphMVkxUUdNeGN5RT0=
  !

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogSignatureFilter).configure(conf)
  end

  def filter(config, messages)
    d = create_driver(config)
    d.run(default_tag: 'test') do
      messages.each do |message|
        d.feed(message)
      end
    end
    # d.filtered_records
  end

  sub_test_case 'configured with invalid configuration' do
    test 'empty configuration' do
      assert_raise(Fluent::ConfigError) do
        create_driver('')
      end
    end
  end

  sub_test_case 'plugin will add some fields' do
    test 'sign the log' do
      conf = CONFIG
      messages = [
        { 'timestamp' => 1691377710875010816, 'message' => 'This is test message', 'secret' => 'abc' }
      ]
      expected = [
        { 'timestamp' => 1691377710875010816, 'message' => 'This is test message', 'secret' => 'abc', 'signature' => 'e3aef099fe612c04844430e7e8b959c2fe31685576ea72ae416b18f840b60a8a' }
      ]
      filtered_records = filter(conf, messages)
      assert_equal(expected, filtered_records)
    end
    # ...
  end

end
