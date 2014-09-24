Gem::Specification.new do |s|
  s.name = "zssl"
  s.version = "0.0.1"
  s.licenses = ["MIT"]
  s.homepage = "https://github.com/pcarranza/zssl"
  s.summary = "Extremely simple encryption and decryption tool based on ssh public and private RSA keys"
  s.description = <<-eos 
            By using a RSA public key (your ssh keys), this script will mimic the SSL encryption 
            algorithm (handshake with a public key, then encryption with a shared key)
            this way the asymetric limitation of encrypting something bigger than the key
            size gets overriden
  eos
  s.author = "Pablo Carranza"
  s.email = "pcarranza@gmail.com"
  s.files = ["lib/zssl.rb", 'lib/zssl_options.rb']
  s.executables << "zssl"
end


