Gem::Specification.new do |spec|
  spec.name = "zssl"
  spec.version = "0.1.0"
  spec.licenses = ["MIT"]
  spec.homepage = "https://github.com/pcarranza/zssl"
  spec.summary = "Enveloped encryption for secure file sharing based on ssh RSA keypairs"
  spec.description = <<-eos 
            By using a RSA public key loaded from your ssh key, this tool will create
            an evenloped encryption: shared key encrypted with RSA and the file with 
            AES256 CBC. Providing strong encryption for any file size, only sharing
            ssh public key.
  eos
  spec.author = "Pablo Carranza"
  spec.email = "pcarranza@gmail.com"
  spec.files = ["lib/zssl.rb"]
  spec.executables << "zssl"

  spec.add_runtime_dependency 'main', '~> 6.0'
end
