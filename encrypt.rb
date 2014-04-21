
class Encrypter

    attr_reader :key

    def initialize(key)
        raise ArgumentError.new "Key cannot be nil" if key.nil?
        raise ArgumentError.new "Key must be public" unless key.public?
        @key = key
    end

    def encrypt(text)
        raise ArgumentError.new "Invalid text" if text.nil? or text.empty?
        key.public_encrypt text
    end

end
