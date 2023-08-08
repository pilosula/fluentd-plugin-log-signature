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
  !

  # test "failure" do
  #   flunk
  # end

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
        { 'timestamp' => 1691377710875010816, 'message' => 'This is test message', 'secret' => 'abc', 'signature' => 'd3ac86e3de6f3a54cfe205be9722bbc498854c1e03e3d0ed2067eff65fb29b0a' }
      ]
      filtered_records = filter(conf, messages)
      assert_equal(expected, filtered_records)
    end
    # ...
  end

end
