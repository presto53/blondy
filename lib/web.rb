module Blondy
  class Web < Sinatra::Base
    include Blondy::Data
    set :root, File.expand_path('../../', __FILE__)
    enable :sessions
    register Sinatra::Flash

    before /^\/(?!(config|login|logout|host\/action))/ do
      authorize!
    end

    get '/login' do
      redirect '/groups' if session[:logged_in]
      haml :login
    end

    get '/logout' do
      session[:logged_in] = false
      redirect '/login'
    end

    post '/login' do
      case CONFIG['auth']
      when 'ldap'
	session[:logged_in] = true if ldap_auth(params[:login], params[:password])
      when 'local'
	session[:logged_in] = true if local_auth(params[:login], params[:password])
      else
	flash[:error] = 'Wrong auth scheme in config.'
	redirect '/login'
      end
	redirect '/'
    end

    get '/' do
      redirect '/groups'
    end

    get '/groups' do
      @groups = HostGroup.all
      haml :groups
    end

    get '/group/:id' do
      @hosts = Host.where(host_group: HostGroup.find(params[:id]))
      @group = HostGroup.find(params[:id])
      haml :hosts
    end

    post '/group/create' do
      group = HostGroup.new
      group.name = params[:name]
      group.valid? ? group.save : flash[:error] = group.errors.messages
      redirect '/groups'
    end

    get '/dhcp' do
      @configs = DhcpConfig.all
      haml :dhcp
    end

    get '/dhcp/create' do
      @id = 0
      @config = DhcpConfig.new
      @dhcp_pools = DhcpPool.all
      haml :dhcp_config
    end

    get '/dhcp/delete' do
      config = DhcpConfig.find(params[:id])
      config.delete if config
      redirect '/dhcp'
    end

    get '/dhcp/:id' do
      @id = params[:id]
      @config = DhcpConfig.find(@id)
      @dhcp_pools = DhcpPool.all
      redirect '/dhcp' unless @config
      haml :dhcp_config
    end

    post '/dhcp/create' do
      config = DhcpConfig.new
      params.each {|param, value| config[param] = value if config.fields.include?(param)}
      config.valid? ? config.save : flash[:error] = config.errors.messages
      redirect '/dhcp'
    end

    post '/dhcp/update' do
      config = DhcpConfig.find(params[:id])
      if config
	params.each {|param, value| config[param] = value if config.fields.include?(param)}
	config.valid? ? config.save : flash[:error] = config.errors.messages
      end
      redirect '/dhcp'
    end

    get '/installer' do
      @configs = InstallerConfig.all
      haml :installer
    end

    get '/installer/create' do
      @id = 0
      @config = InstallerConfig.new
      @text_configs = list_configs
      @install_scripts = list_scripts
      haml :installer_config
    end

    get '/installer/delete' do
      config = InstallerConfig.find(params[:id])
      config.delete if config
      redirect '/installer'
    end

    get '/installer/:id' do
      @id = params[:id]
      @config = InstallerConfig.find(@id)
      @text_configs = list_configs
      @install_scripts = list_scripts
      redirect '/installer' unless @config
      haml :installer_config
    end

    post '/installer/create' do
      config = InstallerConfig.new
      params.each {|param, value| config[param] = value if config.fields.include?(param)}
      config.valid? ? config.save : flash[:error] = config.errors.messages
      redirect '/installer'
    end

    post '/installer/update' do
      config = InstallerConfig.find(params[:id])
      if config
	params.each {|param, value| config[param] = value if config.fields.include?(param)}
	config.valid? ? config.save : flash[:error] = config.errors.messages
      end
      redirect '/installer'
    end

    get '/network' do
      @networks = Network.all
      haml :network
    end

    get '/network/create' do
      @id = 0
      @network = Network.new
      haml :network_config
    end

    get '/network/delete' do
      network = Network.find(params[:id])
      network.delete if network
      redirect '/network'
    end

    get '/network/:id' do
      @id = params[:id]
      @network = Network.find(@id)
      redirect '/network' unless @network
      haml :network_config
    end

    post '/network/create' do
      network = Network.new
      params.each {|param, value| network[param] = value if network.fields.include?(param)}
      network.valid? ? network.save : flash[:error] = network.errors.messages
      redirect '/network'
    end

    post '/network/update' do
      network = Network.find(params[:id])
      if network
	params.each {|param, value| network[param] = value if network.fields.include?(param)}
	network.valid? ? network.save : flash[:error] = network.errors.messages
      end
      redirect '/network'
    end

    get '/dhcp_pool' do
      @dhcp_pools = DhcpPool.all
      haml :dhcp_pool
    end

    get '/dhcp_pool/create' do
      @id = 0
      @dhcp_pool = DhcpPool.new
      haml :dhcp_pool_config
    end

    get '/dhcp_pool/delete' do
      dhcp_pool = DhcpPool.find(params[:id])
      dhcp_pool.delete if dhcp_pool
      redirect '/dhcp_pool'
    end

    get '/dhcp_pool/:id' do
      @id = params[:id]
      @dhcp_pool = DhcpPool.find(@id)
      redirect '/dhcp_pool' unless @dhcp_pool
      haml :dhcp_pool_config
    end

    post '/dhcp_pool/create' do
      dhcp_pool = DhcpPool.new
      params.each {|param, value| dhcp_pool[param] = value if dhcp_pool.fields.include?(param)}
      dhcp_pool.valid? ? dhcp_pool.save : flash[:error] = dhcp_pool.errors.messages
      redirect '/dhcp_pool'
    end

    post '/dhcp_pool/update' do
      dhcp_pool = DhcpPool.find(params[:id])
      if dhcp_pool
	params.each {|param, value| dhcp_pool[param] = value if dhcp_pool.fields.include?(param)}
	dhcp_pool.valid? ? dhcp_pool.save : flash[:error] = dhcp_pool.errors.messages
      end
      redirect '/dhcp_pool'
    end

    get '/host/create' do
      @id = 0
      @host = Host.new
      @dhcp_configs = DhcpConfig.all
      @installer_configs = InstallerConfig.all
      @host_groups = HostGroup.all
      haml :host_config
    end

    get '/host/delete' do
      host = Host.find(params[:id])
      group = host.host_group.id
      host.delete
      redirect "/group/#{group}"
    end

    get '/host/:id' do
      @id = params[:id]
      @host = Host.find(params[:id])
      @dhcp_configs = DhcpConfig.all
      @installer_configs = InstallerConfig.all
      @host_groups = HostGroup.all
      redirect '/groups' unless @host
      haml :host_config
    end

    post '/host/create' do
      host = Host.new
      params.each {|param, value| host[param] = value if host.fields.include?(param)}
      host.valid? ? host.save : flash[:error] = host.errors.messages
      redirect '/groups' unless host.valid?
      redirect "/group/#{host.host_group.id}"
    end

    post '/host/update' do
      host = Host.find(params[:id])
      if host
	params.each {|param, value| host[param] = value if host.fields.include?(param)}
	host.valid? ? host.save : flash[:error] = host.errors.messages
	redirect "/group/#{Host.find(params[:id]).host_group.id}"
      else
	redirect '/groups'
      end
    end

    get '/host/action/:action' do
      params[:id] ? host = Host.find(params[:id]) : host = Host.find_by(hwaddr: params[:hwaddr])
      if host && params[:type]
	case params[:type]
	when "pxeboot"
	  params[:action] == "enable" ? host.netboot = true : host.netboot = false
	when "install"
	  params[:action] == "enable" ? host.install_status = true : host.install_status = false
	end
	host.save
	redirect "/group/#{host.host_group.id}"
      else
	redirect '/groups'
      end
    end

    get '/config/installer/:hwaddr' do
      host = Host.find_by(hwaddr: params[:hwaddr])
      if host
        return 403 unless host.netboot
	net_config = network_settings(host.hostname)
	if net_config.empty?
	  status 403
	else
	  fields = host.installer_config.fields.keys.delete_if {|field| Blondy::Data::Filters::INTERNAL_FIELD =~ field}
	  reply = Array.new
	  install_script = String.new
	  config = String.new
	  File.open("#{CONFIG['install_scripts_path']}/#{host.installer_config.install_script}").each { |l| install_script += l unless (/^#/ =~ l || /^\s*#/ =~ l)}
	  File.open("#{CONFIG['text_configs_path']}/#{host.installer_config.config}/config").each { |l| config += l unless (/^#/ =~ l || /^\s*#/ =~ l)}
	  reply << config
	  reply << "HOSTNAME=#{host.hostname}"
	  reply += net_config
	  fields.each { |field| reply << "#{field.to_s.upcase}=\"#{host.installer_config[field].to_s}\"" }
	  reply << install_script
	  content_type "application/octet-stream"
	  response.headers['Content-Disposition'] = "attachment; filename=conf.subr"
	  reply.join("\n")
	end
      else
	status 404
      end
    end

    get '/config/dhcp' do
      return 404 unless params[:hwaddr]
      host = Host.find_by(hwaddr: params[:hwaddr])
      status 404 unless host
      host.checkin = Time.now
      host.save
      if host.netboot
	reply = Hash.new
	fields = host.dhcp_config.fields.keys.delete_if {|field| Blondy::Data::Filters::INTERNAL_FIELD =~ field}
	fields.each do |field|
	  reply[field] = host.dhcp_config[field]
	end
	reply[:yiaddr] = get_ip_address(host)
	reply.to_json
      else
	status 403
      end 
    end

    helpers do
      def base_url
	@base_url ||= "#{request.env['rack.url_scheme']}://#{request.env['HTTP_HOST']}"
      end

      def list_configs
	Dir.entries(CONFIG['text_configs_path']).select do |entry|
	  File.directory? File.join(CONFIG['text_configs_path'],entry) and !(entry =='.' || entry == '..' || /^\./ =~ entry)
	end
      end

      def list_scripts
	Dir.entries(CONFIG['install_scripts_path']).select do |entry|
	  !File.directory? File.join(CONFIG['install_scripts_path'],entry) and !(entry =='.' || entry == '..' || /^\./ =~ entry) and /\.sh$/ =~ entry
	end
      end

      def get_ip_address(host)
	lease = Blondy::Data::DhcpLease.where(host: host).last
	if lease
	  now = Time.now
	  lease.leased_at = now if lease.leased_at + lease.lease_time < now
	  lease.save
	else
	  lease = Blondy::Data::DhcpLease.new
	  lease.ip = get_ip_from_pool(host.dhcp_config.dhcp_pool)
	  lease.host = host
	  lease.leased_at = Time.now
	  lease.save
	end
	lease.ip
      end

      def get_ip_from_pool(pool)
	ip_addresses = IPAddr.new(pool.network).to_range.to_a
	ip_addresses.shift
	ip_addresses.pop
	ip_addresses.each do |ip|
	  @result_ip = ip.to_s
	  break if free_ip?(@result_ip) and !pool.exceptions.split(',').include?(@result_ip)
	end
	@result_ip
      end

      def free_ip?(ip)
	lease = Blondy::Data::DhcpLease.where(ip: ip).last
	if lease
	  lease.leased_at + lease.lease_time < Time.now ? lease.delete : false
	else
	  true
	end
      end

      def seconds_to_string(s)
	# d = days, h = hours, m = minutes, s = seconds
	m = (s / 60).floor
	s = s % 60
	h = (m / 60).floor
	m = m % 60
	d = (h / 24).floor
	h = h % 24
	output = "#{s.to_i} second#{pluralize(s)}" if (s >= 0)
	output = "#{m.to_i} minute#{pluralize(m)}" if (m > 0)
	output = "> #{h.to_i} hour#{pluralize(h)}" if (h > 0)
	output = "> #{d.to_i} day#{pluralize(d)}" if (d > 0)
	return output + ' ago'
      end

      def pluralize number 
	return "s" unless number == 1
	return ""
      end

      def network_settings(hostname)
	host_ip = Resolv.getaddress hostname rescue return Array.new
	Blondy::Data::Network.each do |config|
	  @net_config = config
	  break if IPAddr.new(config.network).include?(host_ip)
	end
	reply = Array.new
	if @net_config
	  reply << "ip_address=#{host_ip}"
	  reply << "subnet=#{@net_config.network.split('/')[1]}"
	  reply << "vlan=#{@net_config.vlan}" unless @net_config.vlan.to_i == 0
	  reply << "defaultrouter=#{IPAddr.new(@net_config.network).to_range.to_a[1].to_s}"
	end
	reply
      end

      def authorize!
	redirect '/login' unless session[:logged_in]
      end

      def local_auth(login,password)
	User.authenticate(params[:login], params[:password])
      end

      def ldap_auth(login,password)
	ldap = Net::LDAP.new
	ldap.host = CONFIG['ldap_server']
	ldap.auth "cn=#{login},#{CONFIG['ldap_bind_dn']}", password
	ldap.bind
      end
    end
  end
end
