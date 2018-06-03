__precompile__()

module Base58
export base58encode, base58decode, base58checkencode, base58checkdecode

import SHA: sha256

if VERSION < v"0.7.0-DEV.3213"
    codeunits(x) = convert(Array{UInt8}, x)
end

struct NotInAlphabetException <: Exception end

const BASE58CHARS = (
    codeunits("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")...,
)
const SPACE = UInt8(' ')
const ZEROBASE58 = UInt8('1')

const REVBASE58CHARS = if VERSION < v"0.7.0-DEV.4455"
    ntuple(i -> findfirst(BASE58CHARS, UInt8(i)) |>
                x -> x == 0 ? typemax(UInt8) : UInt8(x - 1),
           typemax(UInt8))
else
    ntuple(i -> findfirst(isequal(UInt8(i)), BASE58CHARS) |>
                x -> x == nothing ? typemax(UInt8) : UInt8(x - 1),
           typemax(UInt8))
end

const BASE = 58

encode(x::UInt8) = @inbounds return BASE58CHARS[x + 1]

function base58encode(x::T) where T <: Union{DenseArray{UInt8, 1},
                                             NTuple{N, UInt8} where N}

    if length(x) == 0
        return UInt8[]
    end

    n_zeros = 0
    for c in x
        c != 0 && break
        n_zeros += 1
    end

    if n_zeros == length(x)
        return fill(ZEROBASE58, length(x))
    end

    length_result = length(x) * ceil(Int64, log(256) / log(BASE))

    res = zeros(UInt8, (length_result, ))
    l = 0

    i_x = 1
    @inbounds while i_x <= length(x)

        carry = UInt64(x[i_x])

        i = 0
        i_res = length_result
        while (carry != 0 || i < l) && i_res != 1

            carry += 0x100 * res[i_res]
            carry += UInt64(0x100) * UInt64(res[i_res])
            carry, res[i_res] = divrem(carry, UInt64(BASE))

            i_res -= 1
            i += 1
        end

        @assert carry == 0
        l = i
        i_x += 1
    end

    i_res = 1
    @inbounds while i_res < length_result && res[i_res] == 0
        res[i_res] = 0
        i_res += 1
    end

    res = res[i_res-n_zeros:end]
    @inbounds for i in eachindex(res)
        res[i] = encode(res[i])
    end

    res
end

function base58decode(x::T) where T <: Union{DenseArray{UInt8, 1},
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

function base58checkencode(payload::T) where
    T <: Union{DenseArray{UInt8, 1}, NTuple{N, UInt8} where N}

    checksum = sha256(sha256(payload))[1:4]

    base58encode([payload..., checksum...])
end

function base58checkdecode(x::T, check::Bool = true) where
    T <: Union{DenseArray{UInt8, 1}, NTuple{N, UInt8} where N}

    dec = base58decode(x)
    payload = dec[1:end-4]
    checksum = dec[end-3:end]

    if check
        if sha256(sha256(payload))[1:4] != checksum
            throw(ArgumentError("Invalid address"))
        end
    end

    return payload
end

end # module Base58
