require "openssl"
require "base64"
require "securerandom"

module Zoocial

  class Cipher

    attr_reader :pkey, :noise_size

    def initialize(key)
      fail "Key cannot be nil" if key.nil?

      @chunk_size = 1024
      @division_line = '-' * 60
      @pkey = key if key.respond_to? :public_key
      @pkey ||= SSHKey.new(:file => key ).rsa

      case @pkey
      when OpenSSL::PKey::RSA
        @noise_size = @pkey.n.num_bytes >> 1 | @pkey.n.num_bytes >> 2
      when OpenSSL::PKey::DSA
        fail ArgumentError, 'DSA is not supported'
      else
        fail ArgumentError, "Unsupported key #{key}"
      end
    end

    def encrypt(source, target)
      source = Zoocial.open_file source, 'r'
      target = Zoocial.open_file target, 'w'

      cipher, hidden_key = create_cipher

      begin
        target.write Base64.encode64(@pkey.public_encrypt(hidden_key))
        target.write @division_line + "\n"

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
        key, iv = decrypt_header(source)
        cipher = create_decipher key, iv
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
      cipher.key = key
      cipher.iv = iv
      [cipher, create_hidden_key(key, iv)]
    end

    def create_hidden_key key, iv
      seed = [(SecureRandom.random_number * 1_000_000_000_000)].pack("I")
      pos_in_buffer = seed.unpack("I").pop.modulo(@noise_size - 52)
      random_buffer = ""
      begin
        random_buffer += SecureRandom.random_bytes
      end while random_buffer.length <= @noise_size
      first = seed + random_buffer.byteslice(0..pos_in_buffer - 1) + key + iv
      second = random_buffer.byteslice(first.bytesize..@noise_size - 1)
      return first + second
    end

    def read_shared_key_from_buffer buffer
      pos_in_buffer = buffer.byteslice(0..4).unpack("I").pop.modulo(@noise_size - 52) + 4
      return buffer.byteslice(pos_in_buffer, 32), \
        buffer.byteslice(pos_in_buffer + 32, 16)
    end

    def decrypt_header(source)
      buffer = ""
      begin
        line = source.readline.chomp
        if line == @division_line
          break
        end
        buffer += line
      end until source.eof?

      buffer = @pkey.private_decrypt Base64.decode64(buffer)
      key, iv = read_shared_key_from_buffer(buffer)
    end

    def create_decipher(key, iv)
      cipher = OpenSSL::Cipher::AES256.new 'CBC'
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher
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
      @rsa = if source =~ /^ssh-rsa/ then load_ssh_rsa_key(source) end
      @rsa ||= OpenSSL::PKey.read(source)
    end

    private 

    def load_ssh_rsa_key(source)
      rsakey = OpenSSL::PKey::RSA.new
      parts = Array.new

      base64 = source.chomp.split[1]
      keydata = base64.unpack("m").first # Actually this is base64, expanded
      while (keydata.length > 0) # So, while there is data in the expanded b64, no need to make it a while
        dlen = keydata[0, 4].bytes.inject(0) do |a, b| # Get the length of the key type declaration
          (a << 8) + b
        end
        data = keydata[4, dlen] # Key type declaration
        keydata = keydata[(dlen + 4)..-1] # The actual key
        parts.push(data) # push the data into the parts array
      end
      raise ArgumentError, "Unsupported key type #{parts[0]}" unless parts[0] == "ssh-rsa"
      e = parts[1].bytes.inject do |a, b|
        (a << 8) + b
      end
      n = parts[2].bytes.inject do |a, b|
        (a << 8) + b
      end
      rsakey.n = n
      rsakey.e = e
      @rsa = rsakey
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
