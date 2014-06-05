$LOAD_PATH << '.'
require 'mongoid'
require_relative 'filters'

Mongoid.load!("#{ENV['BLONDY_CONFIGPATH'] || File.dirname(__FILE__) + '/../config/'}/mongoid.yml")

module Blondy
  module Data
    class Host
      include Mongoid::Document
      include Blondy::Data::Filters
      belongs_to :dhcp_config
      belongs_to :installer_config
      belongs_to :host_group
      has_one :dhcp_lease
      field :hostname, type: String
      field :hwaddr, type: String
      field :netboot, type: Boolean, default: false
      field :install_status, type: Boolean, default: false
      field :checkin, type: DateTime
      validates :hostname, presence: true, format: { with: HOSTNAME }
      validates :hwaddr, presence: true, format: { with: MAC }
      validates_uniqueness_of :hwaddr
      index({ hwaddr: 1, hostname: 1 }, { unique: true })
    end

    class HostGroup
      include Mongoid::Document
      include Blondy::Data::Filters
      has_many :hosts
      field :name, type: String
      validates :name, presence: true, format: { with: NAME }
    end

    class DhcpConfig
      include Mongoid::Document
      include Blondy::Data::Filters
      belongs_to :dhcp_pool
      has_many :hosts
      field :name, type: String
      field :gw, type: String
      field :netmask, type: String
      field :dns, type: String
      field :domain, type: String
      field :fname, type: String
      validates :name, presence: true, format: { with: NAME }
      validates :gw, presence: true, format: { with: IP }
      validates :netmask, presence: true, format: { with: NETMASK }
      validates :dns, presence: true, format: { with: IP }
      validates :domain, presence: true, format: { with: DOMAIN }
      validates :fname, presence: true, format: { with: FILENAME }
    end

    class InstallerConfig
      include Mongoid::Document
      include Blondy::Data::Filters
      has_many :hosts
      field :name, type: String
      field :config, type: String, default: 'default'
      field :install_script, type: String, default: 'default'
      field :kernel, type: String, default: 'GENERIC'
      field :packageroot, type: String
      validates :name, presence: true, format: { with: NAME }
      validates :config, presence: true, format: { with: DIRNAME }
      validates :install_script, presence: true, format: { with: FILENAME }
      validates :kernel, presence: true, format: { with: KERNEL }
      validates :packageroot, presence: true, format: { with: PACKAGEROOT }
    end

    class DhcpLease
      include Mongoid::Document
      include Blondy::Data::Filters
      belongs_to :host
      field :ip, type: String
      field :leased_at, type: DateTime
      field :lease_time, type: Integer, default: 600
      validates :ip, presence: true, format: { with: IP }
    end

    class DhcpPool
      include Mongoid::Document
      include Blondy::Data::Filters
      has_many :dhcp_configs
      field :name, type: String
      field :network, type: String
      field :exceptions, type: String
      validates :name, presence: true, format: { with: NETWORK_NAME }
      validates :network, presence: true, format: { with: NETWORK }
      validates :exceptions, presence: true, format: { with: EXCEPTIONS }
    end

    class Network
      include Mongoid::Document
      include Blondy::Data::Filters
      field :name, type: String
      field :network, type: String
      field :vlan, type: String, default: 'none'
      validates :name, presence: true, format: { with: NETWORK_NAME }
      validates :network, presence: true, format: { with: NETWORK }
      validates :vlan, presence: true, format: { with: VLAN }
    end

    class User
      include Mongoid::Document
      field :username, type: String
      field :password, type: String
      validates_uniqueness_of :username

      def self.authenticate(username,password)
	salt = Blondy::Web::CONFIG['password_salt']
	user = self.where(username: username).last
	(user && user.password == Digest::MD5.hexdigest(password+salt)) ? user : false
      end
    end
  end
end
