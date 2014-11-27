require "openssl"
require "base64"
require "securerandom"

module Zoocial

  class Cipher

    attr_reader :pkey

    def initialize(key)
      fail "Key is required" if key.nil?

      @chunk_size = 1024
      @division_line = '-' * 60
      @pkey = key if key.respond_to? :public_key
      @pkey ||= SSHKey.new(:file => key ).rsa

      case @pkey
      when OpenSSL::PKey::RSA
      when OpenSSL::PKey::DSA
        fail ArgumentError, 'DSA is not supported'
      else
        fail ArgumentError, "Unsupported key #{key}"
      end
    end

    def encrypt(source, target)
      source = Zoocial.open_file source, 'r'
      target = Zoocial.open_file target, 'w'

      begin
        cipher = create_cipher do |key, iv|
          buffer = [key, iv].join
          buffer = Base64.encode64(@pkey.public_encrypt(buffer))
          target.write(buffer)
          target.write(@division_line + "\n")
        end
        encrypted = ""
        begin
          chunk = source.read(@chunk_size)
          encrypted += cipher.update(chunk)
          encrypted += cipher.final if source.eof?
          while encrypted.length >= 45
            target.write Base64.encode64(encrypted.slice!(0..44))
          end
        end until source.eof?
        target.write Base64.encode64 encrypted
      rescue Interrupt
        puts "Operation canceled by the user"
      ensure
        target.close unless target.tty?
        source.close unless source.tty?
      end
    end

    def decrypt(source, target)
      source = Zoocial.open_file source, 'r'
      target = Zoocial.open_file target, 'w'
      begin
        cipher = create_decipher(source)
        begin
          chunk = Base64.decode64(source.readline)
          target.write cipher.update(chunk)
        end until source.eof?
        target.write cipher.final
      rescue Interrupt
        puts "Operation canceled by the user"
      ensure
        target.close unless target.tty?
        source.close unless source.tty?
      end
    end

    private

    def create_cipher
      cipher = OpenSSL::Cipher::AES256.new 'CBC'
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      if block_given?
        yield key, iv
      end
      cipher.key = key
      cipher.iv = iv
      cipher
    end

    def create_decipher(source)
      read_key(source) do |key, iv|
        cipher = OpenSSL::Cipher::AES256.new 'CBC'
        cipher.decrypt
        cipher.key = key
        cipher.iv = iv
        cipher
      end
    end

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

  class Options
    attr_reader :mode, :source, :target, :key

    def initialize(args={})
      @source = args.fetch(:source) { :stdin }
      @target = args.fetch(:target) { :stdout }
      @key = args.fetch(:key) { :ssh_id_rsa }
      @mode = case args.fetch(:mode) { fail ArgumentError, "Mode is mandatory" }
              when /^e(ncrypt)?$/i
                :encrypt
              when /^d(ecrypt)?$/i
                :decrypt
              else
                raise ArgumentError, "Invalid mode"
              end
    end

  end

  class SSHKey

    attr_reader :rsa

    def initialize(args={})
      source_file = args.fetch(:file) { fail ArgumentError, "Filename is required" }
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

      skip_key_type_length = parse_data(keydata.slice!(0, 4))
      keydata.slice!(0, skip_key_type_length)

      rsakey = OpenSSL::PKey::RSA.new
      exponent_length = parse_data(keydata.slice!(0, 4))
      rsakey.e = parse_data(keydata.slice!(0, exponent_length))

      modulus_length = parse_data(keydata.slice!(0, 4))
      rsakey.n = parse_data(keydata.slice!(0, modulus_length))

      @rsa = rsakey
    end

    def decode_key(source)
      base64 = source.chomp.split[1]
      keydata = base64.unpack("m").first
      keydata
    end

    def parse_data(data)
      data.bytes.inject(0) do |sum, byte|
        (sum << 8) + byte
      end
    end

  end

  private

  def self.open_file file, mode
    case file
    when String
      File.open file, mode
    when File, IO
      file
    else
      raise ArgumentError, "Invalid file #{file}"
    end
  end

  def self.read_file file
    f = Zoocial.open_file file, 'r'
    f.read
  end
end
