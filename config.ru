$LOAD_PATH << '.'
require 'bundler/setup'
Bundler.require(:default)
require 'thin'
require 'sinatra'
require 'sinatra/flash'
require 'haml'
require 'lib/datamodel'
require 'lib/web'
require 'open-uri'
require 'json'
require 'yaml'
require 'ipaddr'

Mongoid.raise_not_found_error = false

module Blondy
  class Web
    # Load config from file
    begin
      CONFIG = YAML::load(File.open(File.dirname(__FILE__) + '/config/config.yml'))
    rescue
      STDERR.puts "No config file. \nPlease check that config.yml exist."
      exit 1
    end
  end
end

map "/" do
  run Blondy::Web
end
