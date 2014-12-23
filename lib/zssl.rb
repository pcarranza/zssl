require "openssl"
require "base64"
require "securerandom"
require "forwardable"

module Zoocial

  class Cipher

    attr_reader :pkey

    def initialize(key)
      fail "A key is required" if key.nil?

      @chunk_size = 1024
      @division_line = "-" * 60
      @pkey = key if key.respond_to? :public_key
      @pkey ||= SSHKey.new(:file => key ).rsa

      case @pkey
      when OpenSSL::PKey::RSA then
      when OpenSSL::PKey::DSA then fail ArgumentError, "DSA is not supported"
      else fail ArgumentError, "Unsupported key #{key}"
      end
    end

    def encrypt(source, target)
      source = WrapFile.reader(source)
      target = WrapFile.writer(target)
      shared_key = SharedKey.new
      begin
        target.write_b64(@pkey.public_encrypt(shared_key.to_s))
        target.write(@division_line + "\n")
        cipher = shared_key.to_cipher
        encrypted = ""
        begin
          chunk = source.read(@chunk_size)
          encrypted += cipher.update(chunk)
          encrypted += cipher.final if source.eof?
          while encrypted.length >= 45
            target.write_b64(encrypted.slice!(0..44))
          end
        end until source.eof?
        target.write_b64(encrypted)
      rescue Interrupt
        $stderr.puts "Operation canceled by the user"
      ensure
        target.close
        source.close
      end
    end

    def decrypt(source, target)
      source = WrapFile.reader(source)
      target = WrapFile.writer(target)
      begin
        decipher = read_key(source) do |key, iv|
          SharedKey.new(key, iv).to_decipher
        end
        begin
          chunk = source.read_b64_line
          target.write(decipher.update(chunk))
        end until source.eof?
        target.write(decipher.final)
      rescue Interrupt
        $stderr.puts "Operation canceled by the user"
      ensure
        target.close
        source.close
      end
    end

    private

    def read_key(source)
      buffer = ""
      loop do
        key_line = source.readline.chomp
        break if key_line == @division_line
        buffer << key_line << "\n"
      end
      buffer = @pkey.private_decrypt(Base64.decode64(buffer))
      yield buffer.byteslice(0..32), buffer.byteslice(32..-1)
    end

  end

  class SharedKey

    def initialize(key=nil, iv=nil)
      cipher = new_cipher
      @key = key ||= cipher.random_key
      @iv = iv ||= cipher.random_iv
    end

    def to_s
      [@key, @iv].join
    end

    def to_cipher
      new_cipher do |cipher| cipher.encrypt end
    end

    def to_decipher
      new_cipher do |cipher| cipher.decrypt end
    end

    private

    def new_cipher
      cipher = OpenSSL::Cipher::AES256.new "CBC"
      yield cipher if block_given?
      cipher.key = @key if @key
      cipher.iv = @iv if @iv
      cipher
    end
  end

  class SSHKey

    attr_reader :rsa

    def initialize(args={})
      source_file = args.fetch(:file) { fail ArgumentError, "File is required" }
      source = if source_file.respond_to?(:read)
                 source_file.read()
               else
                 File.open(source_file) do |file|
                   file.read()
                 end
               end
      @rsa = load_ssh_rsa_key(source)
      @rsa ||= OpenSSL::PKey.read(source)
    end

    private

    def load_ssh_rsa_key(source)
      fail "DSA is not supported" if source =~ /^ssh-dsa/
      return nil unless source =~ /^ssh-rsa/

      keydata = decode_key(source)

      skip_key_type_length = bytes_to_number(keydata.slice!(0, 4))
      keydata.slice!(0, skip_key_type_length)

      rsakey = OpenSSL::PKey::RSA.new
      exponent_length = bytes_to_number(keydata.slice!(0, 4))
      rsakey.e = bytes_to_number(keydata.slice!(0, exponent_length))

      modulus_length = bytes_to_number(keydata.slice!(0, 4))
      rsakey.n = bytes_to_number(keydata.slice!(0, modulus_length))

      @rsa = rsakey
    end

    def decode_key(source)
      base64 = source.chomp.split[1]
      keydata = base64.unpack("m").first
      keydata
    end

    def bytes_to_number(data)
      data.bytes.inject(0) do |sum, byte|
        (sum << 8) + byte
      end
    end

  end

  class WrapFile
    extend Forwardable

    def_delegators :@file, :read, :write, :readline, :eof?

    def self.reader(file)
      self.new(file, "r")
    end
    def self.writer(file)
      self.new(file, "w")
    end
    def close
      @file.close if @should_close
    end
    def write_b64(buffer)
      write Base64.encode64(buffer)
    end
    def read_b64_line
      Base64.decode64(readline)
    end

    private

    def initialize(file, mode)
      @file = case file
              when String
                @should_close = true
                File.open(file, mode)
              when File, IO then file
              else raise ArgumentError, "Invalid file #{file}"
              end
    end
  end

end
