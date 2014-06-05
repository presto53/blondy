module Blondy
  module Data
    module Filters
      # Regexp filters
      ID=/^[a-fA-F0-9]{24}$/
      MAC=/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/
      PACKAGEROOT=/^[a-zA-Z0-9:_&\/.%$-]+$/
      KERNEL=/^[a-zA-Z0-9._-]+$/
      FILENAME=/^[a-zA-Z0-9._\/-]+$/
      DIRNAME=/^[a-zA-Z0-9._-]+$/
      HOSTNAME=/^[a-zA-Z0-9.-]+$/
      NAME=/^[a-zA-Z0-9. _-]+$/
      RAID=/^[a-zA-Z0-9]+$/
      DOMAIN=/^[a-zA-Z0-9]+\.?[a-zA-Z]*$/
      REQUEST_TYPE=/^(discover)|(request)|(none)$/
      INTERNAL_FIELD=/(^_)|(_id$)/
      NETWORK_NAME=/^[a-zA-Z0-9._\/-]+$/
      IP=/^(((2?5?[0-5])|(2?[0-4]?[0-9])|([01]?[0-9]{2}?))\.){3}((2?5?[0-5])|(2?[0-4]?[0-9])|([01]?[0-9]{2}?))$/
      NETWORK=/^(((2?5?[0-5])|(2?[0-4]?[0-9])|([01]?[0-9]{2}?))\.){3}((2?5?[0-5])|(2?[0-4]?[0-9])|([01]?[0-9]{2}?))\/(([8,9])|([1,2][0-9])|(3[0-2]))$/
      EXCEPTIONS=/^((((2?5?[0-5])|(2?[0-4]?[0-9])|([01]?[0-9]{2}?))\.){3}((2?5?[0-5])|(2?[0-4]?[0-9])|([01]?[0-9]{2}?))|,)*$/
      NETMASK=/^([89])|([12][0-9])|(3[0-2])$/
      VLAN=/^([0-9]{1,4})|(none)$/
    end
  end
end