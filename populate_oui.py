#!/usr/bin/env python3
"""
Populate OUI database with common manufacturers
This script creates a local OUI database when internet access is limited
"""

from app import app, db
from models import OUI

def populate_oui_database():
    """Populate OUI database with common manufacturers"""
    
    # Comprehensive list of common OUI prefixes and manufacturers
    oui_data = {
        # Apple
        '001A2B': 'Apple, Inc.',
        '000393': 'Apple, Inc.',
        'ACDE48': 'Apple, Inc.',
        'B8E856': 'Apple, Inc.',
        'F01898': 'Apple, Inc.',
        'A45E60': 'Apple, Inc.',
        '4C3275': 'Apple, Inc.',
        '78CA39': 'Apple, Inc.',
        'BC52B7': 'Apple, Inc.',
        '3451C9': 'Apple, Inc.',
        '9803D8': 'Apple, Inc.',
        'E4C63D': 'Apple, Inc.',
        'A8667F': 'Apple, Inc.',
        
        # Samsung
        '001EB2': 'Samsung Electronics Co.,Ltd',
        'E8508B': 'Samsung Electronics Co.,Ltd',
        '342387': 'Samsung Electronics Co.,Ltd',
        '0012FB': 'Samsung Electronics Co.,Ltd',
        'DC7196': 'Samsung Electronics Co.,Ltd',
        'E81132': 'Samsung Electronics Co.,Ltd',
        '002454': 'Samsung Electronics Co.,Ltd',
        'C8F733': 'Samsung Electronics Co.,Ltd',
        
        # Cisco Systems
        '001122': 'Cisco Systems, Inc',
        '000CCE': 'Cisco Systems, Inc',
        '001EF7': 'Cisco Systems, Inc',
        '002698': 'Cisco Systems, Inc',
        '0024F7': 'Cisco Systems, Inc',
        '6CAB31': 'Cisco Systems, Inc',
        
        # Google/Nest
        '44070B': 'Google, Inc.',
        'AC63BE': 'Google, Inc.',
        'F4F5D8': 'Google, Inc.',
        'B4A5EF': 'Google, Inc.',
        '1858EF': 'Google, Inc.',
        
        # Xiaomi
        '34CE00': 'Xiaomi Communications Co Ltd',
        '508F4C': 'Xiaomi Communications Co Ltd',
        '7811DC': 'Xiaomi Communications Co Ltd',
        '8CFABA': 'Xiaomi Communications Co Ltd',
        '8C53C3': 'Xiaomi Communications Co Ltd',
        
        # VMware
        '000C29': 'VMware, Inc.',
        '005056': 'VMware, Inc.',
        '001C14': 'VMware, Inc.',
        
        # Raspberry Pi
        'B827EB': 'Raspberry Pi Foundation',
        'DCA632': 'Raspberry Pi Foundation',
        'E45F01': 'Raspberry Pi Foundation',
        '2C4D79': 'Raspberry Pi Foundation',
        
        # Intel Corporation
        '001B21': 'Intel Corporation',
        '3C970E': 'Intel Corporation',
        '009027': 'Intel Corporation',
        '0015F2': 'Intel Corporation',
        '001E64': 'Intel Corporation',
        
        # TP-Link
        'E8DE27': 'TP-Link Technologies Co.,Ltd.',
        'A0F3C1': 'TP-Link Technologies Co.,Ltd.',
        'AC84C6': 'TP-Link Technologies Co.,Ltd.',
        '14CC20': 'TP-Link Technologies Co.,Ltd.',
        '2C4D79': 'TP-Link Technologies Co.,Ltd.',
        
        # NETGEAR
        '001B44': 'Netgear',
        '28C68E': 'Netgear',
        'A00460': 'Netgear',
        '9C3DCF': 'Netgear',
        '204E7F': 'Netgear',
        
        # D-Link
        '001B11': 'D-Link Corporation',
        '14D64D': 'D-Link Corporation',
        '1C7EE5': 'D-Link Corporation',
        'C8BE19': 'D-Link Corporation',
        
        # Realtek
        '00E04C': 'Realtek Semiconductor Co., Ltd.',
        '525400': 'Realtek Semiconductor Co., Ltd.',
        '001E2A': 'Realtek Semiconductor Co., Ltd.',
        
        # Amazon
        '44650D': 'Amazon Technologies Inc.',
        'F0272D': 'Amazon Technologies Inc.',
        '6837E9': 'Amazon Technologies Inc.',
        '0C47C9': 'Amazon Technologies Inc.',
        
        # Microsoft
        '00125A': 'Microsoft Corporation',
        '7C1E52': 'Microsoft Corporation',
        '1C697A': 'Microsoft Corporation',
        
        # Sonos
        '000E58': 'Sonos, Inc.',
        '5CAAFD': 'Sonos, Inc.',
        'B8E937': 'Sonos, Inc.',
        
        # HP
        '001F29': 'Hewlett Packard Enterprise',
        '705A0F': 'Hewlett Packard Enterprise',
        '9457A5': 'Hewlett Packard Enterprise',
        
        # ASUS
        '001D60': 'ASUSTek COMPUTER INC.',
        '2C56DC': 'ASUSTek COMPUTER INC.',
        'AC9E17': 'ASUSTek COMPUTER INC.',
        '1C872C': 'ASUSTek COMPUTER INC.',
        
        # Philips
        '001788': 'Philips Electronics Nederland B.V.',
        '000DF4': 'Philips Electronics Nederland B.V.',
        '7CB21B': 'Philips Electronics Nederland B.V.',
        
        # LG Electronics
        '001C62': 'LG Electronics',
        '002454': 'LG Electronics',
        '40B395': 'LG Electronics',
        
        # Sony
        '001D0F': 'Sony Corporation',
        '648099': 'Sony Corporation',
        'E0B7B1': 'Sony Corporation',
        
        # Nintendo
        '0019FD': 'Nintendo Co.,Ltd',
        '002709': 'Nintendo Co.,Ltd',
        'CC9E00': 'Nintendo Co.,Ltd',
        
        # Huawei
        '001E10': 'Huawei Technologies Co.,Ltd',
        '84A423': 'Huawei Technologies Co.,Ltd',
        '002EC7': 'Huawei Technologies Co.,Ltd',
        'C83A35': 'Huawei Technologies Co.,Ltd',
        
        # Linksys
        '000C41': 'Linksys',
        '48F8B3': 'Linksys',
        '20AA4B': 'Linksys',
        
        # Tesla
        '4CFCAA': 'Tesla Motors',
        
        # Ring (Amazon)
        '6C8336': 'Ring Inc',
        '98F4AB': 'Ring Inc',
        
        # Nest Labs
        '188B9D': 'Nest Labs Inc.',
        '64169F': 'Nest Labs Inc.',
        
        # Roku
        'B0A737': 'Roku, Inc.',
        'CC6D30': 'Roku, Inc.',
        
        # Canon
        '001E8F': 'Canon Inc.',
        'F81EDF': 'Canon Inc.',
        
        # Brother
        '002586': 'Brother Industries, LTD.',
        '001BA9': 'Brother Industries, LTD.',
        
        # Epson
        '003085': 'Seiko Epson Corporation',
        '805ECB': 'Seiko Epson Corporation',
    }
    
    with app.app_context():
        try:
            # Clear existing OUI data
            OUI.query.delete()
            
            # Add new OUI data
            count = 0
            for prefix, manufacturer in oui_data.items():
                oui = OUI(prefix=prefix.upper(), manufacturer=manufacturer)
                db.session.add(oui)
                count += 1
            
            db.session.commit()
            print(f"Successfully populated OUI database with {count} entries")
            return count
            
        except Exception as e:
            db.session.rollback()
            print(f"Error populating OUI database: {e}")
            return 0

if __name__ == '__main__':
    count = populate_oui_database()
    print(f"OUI database populated with {count} manufacturers")