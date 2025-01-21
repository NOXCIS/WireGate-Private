from flask import Blueprint, request
import subprocess
import json
import os
from ..modules.shared import ResponseObject
from ..modules.models import WireguardConfigurations
from ..modules.shared import sqlSelect, sqlUpdate
from urllib.parse import unquote

traffic_weir_blueprint = Blueprint('traffic_weir', __name__)

PROTOCOL_PATH = "/tmp/wiregate_protocol.json"

@traffic_weir_blueprint.post('/set_peer_rate_limit')
def set_peer_rate_limit():
    """Set traffic rate limit for a WireGuard peer"""
    data = request.get_json()
    
    # Validate required parameters
    if not all(k in data for k in ['interface', 'peer_key', 'rate']):
        return ResponseObject(False, "Missing required parameters")
    
    try:
        # Get configuration object for the interface
        config = WireguardConfigurations.get(data['interface'])
        if not config:
            return ResponseObject(False, f"Interface {data['interface']} not found")
        
        # Find and validate the peer exists
        found, peer = config.searchPeer(data['peer_key'])
        if not found:
            return ResponseObject(False, f"Peer {data['peer_key']} not found in interface {config.Name}")
        
        # Validate rate is a positive number and convert to integer
        try:
            rate = float(data['rate'])
            if rate < 0:
                return ResponseObject(False, "Rate must be a positive number")
            # Convert rate to integer for traffic-weir
            rate_int = int(round(rate))
        except ValueError:
            return ResponseObject(False, "Invalid rate value")
            
        # Validate protocol
        protocol = config.get_iface_proto()
        if protocol not in ["wg", "awg"]:
            return ResponseObject(False, f"Invalid or unsupported protocol: {protocol}")
            
        # Write protocol info to temporary file for traffic-weir
        protocol_info = {"protocol": config.Protocol}
        with open(PROTOCOL_PATH, 'w') as f:
            json.dump(protocol_info, f)
            
        # Store original rate (float) in database
        sqlUpdate(
            "UPDATE '%s' SET rate_limit = ? WHERE id = ?" % config.Name,
            (rate, peer.id)
        )
        
        # Execute traffic-weir command with integer rate
        cmd = [
            './traffic-weir',
            '--interface', config.Name,
            '--peer', peer.id,
            '--rate', str(rate_int)  # Convert to integer
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Clean up temporary file
        try:
            os.remove(PROTOCOL_PATH)
        except:
            pass  # Ignore cleanup errors
        
        if result.returncode != 0:
            return ResponseObject(False, f"Failed to set rate limit: {result.stderr}")
            
        return ResponseObject(True, f"Rate limit set successfully for peer {peer.id} on interface {config.Name}")
        
    except Exception as e:
        # Clean up temporary file in case of error
        try:
            os.remove(PROTOCOL_PATH)
        except:
            pass
        return ResponseObject(False, f"Error setting rate limit: {str(e)}")

@traffic_weir_blueprint.get('/get_peer_rate_limit')
def get_peer_rate_limit():
    """Get traffic rate limit for a WireGuard peer"""
    interface = request.args.get('interface')
    peer_key = unquote(request.args.get('peer_key', ''))
    
    print(f"[DEBUG] Getting rate limit for interface={interface}, peer_key={peer_key}")
    
    if not interface or not peer_key:
        print("[DEBUG] Missing required parameters")
        return ResponseObject(False, "Missing required parameters")
    
    try:
        # Get configuration object for the interface
        config = WireguardConfigurations.get(interface)
        if not config:
            print(f"[DEBUG] Interface {interface} not found")
            return ResponseObject(False, f"Interface {interface} not found")
        
        # Find and validate the peer exists
        found, peer = config.searchPeer(peer_key)
        print(f"[DEBUG] Peer search result: found={found}, peer_id={peer.id if peer else None}")
        
        if not found:
            return ResponseObject(False, f"Peer {peer_key} not found in interface {config.Name}")
            
        # Get rate limit from database
        rate_limit = sqlSelect(
            "SELECT rate_limit FROM '%s' WHERE id = ?" % interface,
            (peer_key,)
        ).fetchone()
        
        print(f"[DEBUG] Database query result: {rate_limit}")
        
        result = ResponseObject(True, "Rate limit retrieved successfully", {
            "rate": rate_limit['rate_limit'] if rate_limit else 0
        })
        print(f"[DEBUG] Returning response: {result.__dict__}")
        return result
        
    except Exception as e:
        print(f"[DEBUG] Error getting rate limit: {str(e)}")
        return ResponseObject(False, f"Error getting rate limit: {str(e)}")