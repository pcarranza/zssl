require "openssl"
require "base64"
require "securerandom"

module Zoocial
    class Cipher

        attr_reader :pkey, :noise_size

        def initialize(key)
            raise ArgumentError, "Key cannot be nil" if key.nil?
            case key
            when OpenSSL::PKey::PKey
                @pkey = key
            when String, File, IO
                text = Zoocial.read_file key
                if text =~ /^ssh-rsa/
                    @pkey = Zoocial.load_ssh_pubkey text
                else
                    @pkey = OpenSSL::PKey.read text
                end
            end
            case @pkey
            when OpenSSL::PKey::RSA
                @noise_size = @pkey.n.num_bytes >> 1 | @pkey.n.num_bytes >> 2
            when OpenSSL::PKey::DSA
                raise ArgumentError, 'DSA is not supported'
            else
                raise ArgumentError, "Unsupported key #{key}"
            end
            @chunk_size = 1024
            @division_line = '-' * 60
        end

        def encrypt(source, target)
            source = Zoocial.open_file source, 'r'
            target = Zoocial.open_file target, 'w'

            cipher = OpenSSL::Cipher::AES256.new 'CBC'
            cipher.encrypt
            key = cipher.random_key 
            iv = cipher.random_iv
            cipher.key = key
            cipher.iv = iv
            hidden_key = hide_shared_key_in_buffer key, iv

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

            buffer = ""
            begin
                begin
                    line = source.readline.chomp
                    if line == @division_line
                        break
                    end
                    buffer += line
                end until source.eof?

                buffer = @pkey.private_decrypt Base64.decode64(buffer)
                key, iv = read_shared_key_from_buffer buffer

                cipher = OpenSSL::Cipher::AES256.new 'CBC'
                cipher.decrypt
                cipher.key = key
                cipher.iv = iv
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

        def hide_shared_key_in_buffer key, iv
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

    end

    private

    def self.load_ssh_pubkey text
        rsakey = OpenSSL::PKey::RSA.new
        text.lines.each do |line|
            base64 = line.chomp.split[1]
            keydata = base64.unpack("m").first
            parts = Array.new
            while (keydata.length > 0)
                dlen = keydata[0, 4].bytes.inject(0) do |a, b|
                    (a << 8) + b
                end
                data = keydata[4, dlen]
                keydata = keydata[(dlen + 4)..-1]
                parts.push(data)
            end
            type = parts[0]
            raise ArgumentError, "Unsupported key type #{type}" unless type == "ssh-rsa"
            e = parts[1].bytes.inject do |a, b|
                (a << 8) + b
            end
            n = parts[2].bytes.inject do |a, b|
                (a << 8) + b
            end
            rsakey.n = n
            rsakey.e = e
        end
        rsakey
    end

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
