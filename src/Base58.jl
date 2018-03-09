module Base58

import SHA: sha256

# import Base: read, write, close, eof, empty!
# export Base58EncodePipe, Base58DecodePipe, base58encode, base58decode

if VERSION < v"0.7.0-DEV.3213"
    codeunits(x) = convert(Array{UInt8}, x)
end

struct NotInAlphabetException <: Exception end

# struct Base58
#     data::Vector{UInt8}
# end
# struct Base58Check
#     data::Vector{UInt8}
# end

const BASE58CHARS = (
    codeunits("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")...,
)
const SPACE = UInt8(' ')
const ZEROBASE58 = UInt8('1')

const REVBASE58CHARS = ntuple(i -> findfirst(BASE58CHARS, UInt8(i)) |>
                                   x -> x == 0 ? typemax(UInt8) : UInt8(x - 1),
                              typemax(UInt8))

const BASE = 58

function base58encode(x::T) where T <: Union{Array{UInt8, 1},
                                             NTuple{N, UInt8} where N}

    if length(x) == 0
        return codeunits("")
    end

    n_zeros = 0
    while n_zeros < length(x) && x[n_zeros + 1] == 0
        n_zeros += 1
    end

    length_result = length(x) * ceil(Int, log(256) / log(BASE))

    if n_zeros == length(x)
        return fill(ZEROBASE58, length(x))
    end

    res = zeros(UInt8, (length_result, ))
    l = 0

    i_x = 1
    while i_x <= length(x)

        carry = x[i_x]

        i = 0
        i_res = length_result
        while (carry != 0 || i < l) && i_res != 1

            carry += 0x100 * res[i_res]
            res[i_res] = carry % BASE
            carry = div(carry, BASE)

            i_res -= 1
            i += 1
        end

        @assert carry == 0
        l = i
        i_x += 1
    end

    i_res = 1
    while i_res < length_result && res[i_res] == 0
        res[i_res] = 0
        i_res += 1
    end

    res = res[i_res-n_zeros:end]
    for i in eachindex(res)
        res[i] = BASE58CHARS[res[i] + 1]
    end

    res
end

function base58decode(x::T) where T <: Union{Array{UInt8, 1},
                                             NTuple{N, UInt8} where N}

    i = 1
    while i <= length(x) && x[i] == SPACE
        i += 1
    end

    n_zeros = 0
    while i <= length(x) && x[i] == ZEROBASE58
        n_zeros += 1
        i += 1
    end

    out_size = (length(x) - n_zeros) * ceil(Int, log(58) / log(256))
    res = zeros(UInt8, out_size)

    l = 0
    while i <= length(x) && x[i] != SPACE

        carry = REVBASE58CHARS[x[i]]
        if carry == typemax(UInt8)
            throw(ArgumentError("Letter not in Base58 alphabet"))
        end

        j = 0
        k = length(res)
        while (carry != 0 || j < l) && k > 0

            carry +=  58 * res[k]
            carry, res[k] = divrem(carry, 256)

            k -= 1
            j += 1
        end

        @assert carry == 0

        l = i
        i += 1
    end

    while i < length(x) && x[i] == SPACE
        i += 1
    end

    if length(res) > 0

        i = 1
        while i <= length(res) && res[i] == 0
            i += 1
        end

        append!(zeros(UInt8, n_zeros), res[i:end])
    elseif n_zeros > 0
        zeros(UInt8, n_zeros)
    else
        res
    end
end


# Bitcoin specific constants

# Table from https://en.bitcoin.it/wiki/List_of_address_prefixes

# Decimal prefix Hex       Example use                                     Leading Symbol(s) Example
# -----------------------------------------------------------------------------------------------------------
# 0              00        Pubkey hash (P2PKH address)                     1                 17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem
# 5              05        Script hash (P2SH address)                      3                 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
# 128            80        Private key (WIF, uncompressed pubkey)          5                 5Hwgr3u458GLafKBgxtssHSPqJnYoGrSzgQsPwLFhLNYskDPyyA
# 128            80        Private key (WIF, compressed pubkey)            K or L            L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ
# 4 136 178 30   0488B21E  BIP32 pubkey                                    xpub              xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5e4cp9LB
# 4 136 173 228  0488ADE4  BIP32 private key                               xprv              xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx
# 111            6F        Testnet pubkey hash                             m or n            mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
# 196            C4        Testnet script hash                             2                 2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc
# 239            EF        Testnet Private key (WIF, uncompressed pubkey)  9                 92Pg46rUhgTT7romnV7iGW6W1gbGdeezqdbJCzShkCsYNzyyNcc
# 239            EF        Testnet Private key (WIF, compressed pubkey)    c                 cNJFgo1driFnPcBdBX8BrJrpxchBWXwXCvNH5SoSkdcF6JXXwHMm
# 4 53 135 207   043587CF  Testnet BIP32 pubkey                            tpub              tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLNGbhd2pq7ZtDiPYTfJ7iBenLVQpYgSQqPjUsQeJXH8VQ8xA67D
# 4 53 131 148   04358394  Testnet BIP32 private key                       tprv              tprv8ZgxMBicQKsPcsbCVeqqF1KVdH7gwDJbxbzpCxDUsoXHdb6SnTPYxdwSAKDC6KKJzv7khnNWRAJQsRA8BBQyiSfYnRt6zuu4vZQGKjeW4YF 

const P2PKSH  = (0x00, )
const P2SH    = (0x05, )
const WIF     = (0x80, )
const XPUB    = (0x04, 0x88, 0xb2, 0x1e)
const XPRIV   = (0x04, 0x88, 0xad, 0xe4)
const TP2PKSH = (0x6f, )
const TP2SH   = (0xc4, )
const TWIF    = (0xef, )
const TPUB    = (0x04, 0x35, 0x87, 0xcf)
const TPRIV   = (0x04, 0x35, 0x83, 0x94)

function base58checkencode(x::T, prefix::U = P2PKSH) where
    T <: Union{Array{UInt8, 1}, NTuple{N, UInt8} where N} where
    U <: Union{Array{UInt8, 1}, NTuple{N, UInt8} where N}

    base58encode([
        prefix..., x..., sha256(sha256([prefix..., x...]))[1:4]...
    ])
end

function base58checkdecode(x::T, check = true) where
    T <: Union{Array{UInt8, 1}, NTuple{N, UInt8} where N}

    res = base58decode(x[1:end - 4])

    if check
        if sha256(sha256(res[1:end - 4]))[1:4] != res[end - 3:end]
            throw(ArgumentError("Invalid address"))
        end
    end

    return res
end

# base58decode(x::Base58) = base58decode(x.data)

# function Base58Check(x::T) where T<:Union{Array{UInt8, 1}, NTuple{N, UInt8} where N}
#     checksum = SHA.sha256(SHA.sha256(x))
#     Base58Check(Base58(x).string * checksum[end-3:end])
# end

end # module Base58
