-- A simple yet useful Wireshark Lua dissector for EAP-5G (Ref. 3GPP TS 24 502)
-- Copyright (C) 2026 Domenico Verde (verde@romars.tech)

local proto = Proto("eap-5g", "EAP-5G Protocol")
local proto_eap = Dissector.get("eap")
local eap_type = Field.new("eap.type")
local eap_code = Field.new("eap.code")
local eap_vendor_id = Field.new("eap.ext.vendor_id")
local eap_vendor_type = Field.new("eap.ext.vendor_type")
local eap_ext_data = Field.new("data.data")



function is_eap_5g(tvb, pinfo)
	-- Check if Protocol is EAP-Expanded Type (254)
	if (eap_type() == nil or eap_type().value ~= 254) then
		if (eap_type() ~= nil) then
			print("[DEBUG] EAP Type: " .. eap_type().value)
		end
		return false
	end

	-- Check if Vendor-ID is 3GPP (10415 - IANA SMI Private Enterprise Code Registry)
	if (eap_vendor_id() == nil or eap_vendor_id().value ~= 10415) then
		if (eap_vendor_id() ~= nil) then
			print("[DEBUG] EAP-Ext Vendor ID: " .. eap_vendor_id().value)
		end
		return false
	end

	-- Check if is EAP-5G (3 - Ref. TS 33.402)
	if (eap_vendor_type() == nil or eap_vendor_type().value ~= 3) then
		if (eap_vendor_type() ~= nil) then
			print("[DEBUG] EAP-Ext Vendor Type: " .. eap_vendor_type().value)
		end
		return false
	end

	return true
end



function proto.dissector(tvb, pinfo, tree)
	-- Check if Packet contains EAP-5G Payload
	if not is_eap_5g(tvb, pinfo) then
		return nil
	end

	-- Start dissection of EAP-5G Packet (updated to TS 24.502 V17.7.0)
	tree = tree:add(proto, tvb)
	pinfo.cols.protocol = proto.name

	-- Vendor-ID and  Vendor-Type
	tree:add_le("Vendor-ID: 3GPP (10415)")
	tree:add_le("Vendor-Type: EAP-5G (3)")

	-- EAP-5G Message-ID and Spare
	local message_id =  eap_ext_data().range:range(0,1):uint() 	-- Message-Id Field (1 Byte)
	local spare =  eap_ext_data().range:range(1,1):uint()		-- Spare Field (1 Byte)

	if (message_id == 1 and eap_code().value == 1) then
		-- EAP-Request 5G-Start
		pinfo.cols.info = "EAP-5G Request, 5G-Start"
		tree:add_le("Message-ID: 5G-Start (1)")
		tree:add_le("Spare: " .. spare)

	elseif (message_id == 2 and eap_code().value == 1) then
		-- EAP-Request 5G-NAS
		pinfo.cols.info = "EAP-5G Request, 5G-Start"
		tree:add_le("Message-ID: 5G-NAS (2)")
		tree:add_le("Spare: " .. spare)
		tree:add_le("NAS-PDU Length: " .. eap_ext_data().range:range(2,2):uint())
		Dissector.get("nas-5gs"):call(eap_ext_data().range:range(4):tvb(), pinfo, tree)

	elseif (message_id == 2 and eap_code().value == 2) then
		-- EAP-Response 5G-NAS
		pinfo.cols.info = "EAP-5G Response, NAS-5GS"
		tree:add_le("Message-ID: 5G-NAS (2)")
		tree:add_le("Spare: " .. spare)
		local an_length = eap_ext_data().range:range(2,2):uint()
		tree:add_le("AN-parameters Length: " .. an_length)

		-- AN Parameters
		local i = 0		-- sum of an_length
		local n = 1		-- number of an_params
		while i < an_length do
			local an_param_type = eap_ext_data().range:range(4+i,1):uint()
			local an_param_len = eap_ext_data().range:range(5+i,1):uint()
			if (an_param_type == 1) then
				-- Globally Unique AMF ID (GUAMI)
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("Type: GUAMI (1)")
				subtree:add_le("Length: " .. an_param_len)
				-- Value Part
				subtree:add_le("PLMN ID: " .. tostring(eap_ext_data().range:range(6+i,3)))
				subtree:add_le("AMF Full ID: " .. tostring(eap_ext_data().range:range(9+i,3)))
				i = i + an_param_len + 2
				n = n + 1

			elseif (an_param_type == 2) then
				-- Selected PLMN ID
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("Type: selected PLMN ID (2)")
				subtree:add_le("Length: " .. an_param_len)
				-- Value Part
				subtree:add_le("Value: " .. tostring(eap_ext_data().range:range(6+i,3)))
				i = i + an_param_len + 2 	-- Length of selected PLMN ID is 5 octects
				n = n + 1

			elseif (an_param_type == 3) then
				-- Requested NSSAI
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("Type: requested NSSAI (3)")
				subtree:add_le("Length: " .. an_param_len)
				-- Value Part
				subtree:add_le("SST: " .. tostring(eap_ext_data().range:range(7+i,1)))
				subtree:add_le("SD: " .. tostring(eap_ext_data().range:range(8+i,3)))
				i = i + an_param_len + 2
				n = n + 1

			elseif (an_param_type == 4) then
				-- Establishment Cause for Non-3GPP Access
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("Type: establishment cause for non-3GPP access (4)")
				subtree:add_le("Length: " .. an_param_len)
				-- Value Part
				local value = eap_ext_data().range:range(6+i,1):bitfield(4, 4)
				if value == 0 then
					subtree:add_le("N3AEC: emergency (0)")
				elseif value == 1 then
					subtree:add_le("N3AEC: highPriorityAccess (1)")
				elseif value == 3 then
					subtree:add_le("N3AEC: mo-Signalling (3)")
				elseif value == 4 then
					subtree:add_le("N3AEC: mo-Data (4)")
				elseif value == 8 then
					subtree:add_le("N3AEC: mps-PriorityAccess (8)")
				elseif value == 9 then
					subtree:add_le("N3AEC: mcs-PriorityAccess (9)")
				end
				i = i + an_param_len + 2
				n = n + 1

			elseif (an_param_type == 5) then
				-- Selected NID
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("AN-Parameter Type: selected NID (5)")
				subtree:add_le("Length: " .. an_param_len)
				i = i + an_param_len + 2
				n = n + 1

			elseif (an_param_type == 6) then
				-- UE Identity
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("AN-Parameter Type: UE Identity (6)")
				subtree:add_le("Length: " .. an_param_len)
				i = i + an_param_len + 2
				n = n + 1

			else
				print("[DEBUG] Unknown AN-parameter: " .. an_param_type)
				break
			end
		end

		-- 5G NAS PDU
		tree:add_le("NAS-PDU Length: " .. eap_ext_data().range:range(4+an_length,2):uint())
		Dissector.get("nas-5gs"):call(eap_ext_data().range:range(4+an_length+2):tvb(), pinfo, tree)

	elseif (message_id == 3 and eap_code().value == 1) then
		-- EAP-Request 5G-Notification
		pinfo.cols.info = "EAP-5G Request, 5G-Notification"
		tree:add_le("Message-ID: 5G-Notification (3)")
		tree:add_le("Spare: " .. spare)
		local an_length = eap_ext_data().range:range(2,2):uint()
		tree:add_le("AN-Parameters Length: " .. an_length)

		-- AN Parameters
		local i = 0		-- sum of an_length
		local n = 1		-- number of an_params
		while i < an_length do
			local an_param_type = eap_ext_data().range:range(4+i,1):uint()
			local an_param_len = eap_ext_data().range:range(5+i,1):uint()
			if (an_param_type == 1) then
				-- TNGF IPv4 Contact Info
				local subtree = tree:add(proto, tvb(), "AN Parameter " .. n)
				subtree:add_le("AN-Parameter Type: TNGF IPv4 Contact Info (1)")
				subtree:add_le("AN-Parameter Length: " .. an_param_len)
				-- Value Part
				subtree:add_le("AN-Parameter Value: " .. tostring(eap_ext_data().range:range(6+i,4):ipv4()))
				i = i + an_param_len + 2
				n = n + 1

			elseif (an_param_type == 2) then
				-- TNGF IPv6 Contact Info
				local subtree = tree:add(proto, tvb(), "AN Parameter" .. n)
				subtree:add_le("AN-Parameter Type: TNGF IPv6 Contact Info (2)")
				subtree:add_le("AN-Parameter Length: " .. an_param_len)
				-- Value Part
				subtree:add_le("AN-Parameter Value: " .. tostring(eap_ext_data().range:range(6+i,16):ipv6()))
				i = i + an_param_len + 2
				n = n + 1

			else
				print("[DEBUG] Unknown AN-parameter: " .. an_param_type)
				break
			end
		end

	elseif (message_id == 3 and eap_code().value == 2) then
		-- EAP-Response 5G-Notification
		pinfo.cols.info = "EAP-5G Response, 5G-Notification"
		tree:add_le("Message-ID: 5G-Notification (3)")
		tree:add_le("Spare: " .. spare)

	elseif (message_id == 4 and eap_code().value == 1) then
		-- EAP-Request 5G-Stop
		pinfo.cols.info = "EAP-5G Request, 5G-Stop"
		tree:add_le("Message-ID: 5G-Stop (4)")
		tree:add_le("Spare: " .. spare)

	else
		tree:add_le("Message-ID: Unknown (" .. message_id .. ")")
		print("[DEBUG] EAP-5G Message-Id: " .. message_id)
	end
end

register_postdissector(proto)
