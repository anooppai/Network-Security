import ConfigParser

# Server Configuration  entries
config = ConfigParser.RawConfigParser()
config.add_section('DH_config')
config.set('DH_config', 'g', 2)
config.set('DH_config', 'p', '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF')
config.add_section('server_keys')
config.set('server_keys', 'private_key', 'keys/server_private_key.der')
config.set('server_keys', 'public_key', 'keys/server_public_key.der')
config.add_section('passwords')
config.set('passwords', 'filename', 'passwords')
config.add_section('my_address')
config.set('my_address', 'ip_address', '127.0.0.1')
config.set('my_address', 'port', 9090)

# Client configuration entries
clientConfig = ConfigParser.RawConfigParser()
clientConfig.add_section('DH_config')
clientConfig.set('DH_config', 'g', 2)
clientConfig.set('DH_config', 'p', '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF')
clientConfig.add_section('server_keys')
clientConfig.set('server_keys', 'public_key', 'keys/server_public_key.der')
clientConfig.add_section('server_address')
clientConfig.set('server_address', 'ip_address', '127.0.0.1')
clientConfig.set('server_address', 'port', 9090)


# Writing configuration to files
with open('server.cfg', 'wb') as configfile:
    config.write(configfile)

with open('client.cfg', 'wb') as configfile:
    clientConfig.write(configfile)
