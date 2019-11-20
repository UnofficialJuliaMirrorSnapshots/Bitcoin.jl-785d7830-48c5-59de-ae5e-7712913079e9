function get_tx(tx::TxIn)
    return get_tx(bytes2hex(tx.prevout.txid))
end

"""
    value(txin::TxIn) -> Integer

Get the outpoint value by looking up the tx hash
Returns the amount in satoshi
"""
function value(txin::TxIn)
    tx = get_tx(txin)
    return tx.outputs[txin.prevout.index + 1].value
end

"""
    script_pubkey(txin::TxIn) -> Script

Get the scriptPubKey by looking up the tx hash
Returns a Script object
"""
function script_pubkey(txin::TxIn)
    tx = get_tx(txin)
    return tx.outputs[txin.prevout.index + 1].scriptpubkey
end

"""
    id(tx::Tx) -> String

Returns an hexadecimal string of the transaction hash
"""
function id(tx::Tx)
    return bytes2hex(BitcoinPrimitives.hash256(tx))
end

"""
    fee(tx::Tx) -> Integer

Returns the fee of this transaction in satoshi
"""
function fee(tx::Tx)
    input_sum, output_sum = 0, 0
    for tx_in in tx.inputs
        input_sum += value(tx_in)
    end
    for tx_out in tx.outputs
        output_sum += tx_out.value
    end
    return input_sum - output_sum
end

"""
    sig_hash(tx::Tx, input_index::Integer)::Vector{UInt8}

Returns the hash that needs to get signed for index input_index
"""
function sig_hash(tx::Tx, input_index::Integer, redeem_script::Union{Script,Nothing}=nothing)
    s = Vector(reinterpret(UInt8, [htol(tx.version)]))
    append!(s, encode_varint(length(tx.inputs)))

    i, script_sig = 0, Script()
    for tx_in in tx.inputs
        if i == input_index
            if redeem_script != nothing
                script_sig = redeem_script
            else
                script_sig = script_pubkey(tx_in)
            end
        else
            script_sig = nothing
        end
        prevout = BitcoinPrimitives.Outpoint(tx_in.prevout.txid,
                                             tx_in.prevout.index)
        alt_tx_in = TxIn(prevout,
                         script_sig,
                         tx_in.sequence)

        append!(s, BitcoinPrimitives.serialize(alt_tx_in))
    end
    append!(s, encode_varint(length(tx.outputs)))
    for tx_out in tx.outputs
        append!(s, BitcoinPrimitives.serialize(tx_out))
    end
    append!(s, Vector(reinterpret(UInt8, [htol(tx.locktime)])))
    append!(s, Vector(reinterpret(UInt8, [htol(SIGHASH_ALL)])))
    return hash256(s)
end

function hash_prevouts(tx::Tx)
    all_prevouts = UInt8[]
    for input in tx.inputs
        append!(all_prevouts, reverse!(copy(input.prevout.txid)))
        append!(all_prevouts, reinterpret(UInt8, [htol(input.prevout.index)]))
    end
    return Bitcoin.hash256(all_prevouts)
end

function hash_sequence(tx::Tx)
    all_sequence = UInt8[]
    for input in tx.inputs
        append!(all_sequence, reinterpret(UInt8, [htol(input.sequence)]))
    end
    return hash256(all_sequence)
end

function hash_outputs(tx::Tx)
    if tx._hash_outputs == nothing
        all_outputs = UInt8[]
        for tx_out in tx.tx_outs
            append!(all_outputs, serialize(tx_out))
        end
        tx._hash_outputs = hash256(all_outputs)
    end
    return tx._hash_outputs
end


"""
Returns the integer representation of the hash that needs to get
signed for index input_index
"""
function sig_hash_bip143(tx::Tx, input_index::Integer; redeem_script::Union{Script,Nothing}=nothing, witness_script::Union{Script,Nothing}=nothing)
    tx_in = tx.tx_ins[input_index+1]
    # per BIP143 spec
    s = Vector(reinterpret(UInt8, [htol(tx.version)]))
    append!(s, hash_prevouts(tx))
    append!(s, hash_sequence(tx))
    append!(s, reverse!(copy(tx_in.prev_tx)))
    append!(s, reinterpret(UInt8, [htol(tx_in.prev_index)]))

    if witness_script != nothing
        script_code = serialize(witness_script)
    elseif redeem_script != nothing
        script_code = serialize(p2pkh_script(redeem_script.instructions[2]))
    else
        script_code = serialize(p2pkh_script(script_pubkey(tx_in, tx.testnet).instructions[2]))
    end
    append!(s, script_code)
    append!(s, reinterpret(UInt8, [htol(value(tx_in, tx.testnet))]))
    append!(s, reinterpret(UInt8, [htol(tx_in.sequence)]))
    append!(s, hash_outputs(tx))
    append!(s, reinterpret(UInt8, [htol(tx.locktime)]))
    append!(s, reinterpret(UInt8, [htol(SIGHASH_ALL)]))

    return hash256(s)
end

"""
    verify(tx::Tx, input_index) -> Bool

Returns whether the input has a valid signature
"""
function verify(tx::Tx, input_index)
    tx_in = tx.tx_ins[input_index+1]
    script_pubkey_ = script_pubkey(tx_in, tx.testnet)
    if is_p2sh(script_pubkey_)
        raw_redeem = copy(tx_in.script_sig.instructions[end])
        length_ = UInt8(length(raw_redeem))
        pushfirst!(raw_redeem, length_)
        redeem_script = scriptparse(IOBuffer(raw_redeem))
        if is_p2wpkh(redeem_script)
            z = sig_hash_bip143(tx, input_index, redeem_script=redeem_script)
            witness = tx_in.witness
        elseif is_p2wsh(redeem_script)
            raw_witness = copy(tx_in.witness.instructions[end])
            length_ = encode_varint(length(raw_witness))
            prepend!(raw_witness, length_)
            witness_script = scriptparse(IOBuffer(raw_witness))
            z = sig_hash_bip143(tx, input_index, witness_script=witness_script)
            witness = tx_in.witness
        else
            z = sig_hash(tx, input_index, redeem_script)
            witness = nothing
        end
    else
        if is_p2wpkh(script_pubkey_)
            z = sig_hash_bip143(tx, input_index)
            witness = tx_in.witness
        elseif is_p2wsh(script_pubkey_)
            raw_witness = copy(tx_in.witness.instructions[end])
            length_ = encode_varint(length(raw_witness))
            prepend!(raw_witness, length_)
            witness_script = scriptparse(IOBuffer(raw_witness))
            z = sig_hash_bip143(tx, input_index, witness_script=witness_script)
            witness = tx_in.witness
        else
            z = sig_hash(tx, input_index)
            witness = nothing
        end
    end
    combined_script = Script(copy(tx_in.script_sig.instructions))
    append!(combined_script.instructions, script_pubkey(tx_in, tx.testnet).instructions)
    return evaluate(combined_script, to_int(z), witness)
end


"""
    verify(tx::Tx) -> Bool

Verify transaction `tx`
"""
function verify(tx::Tx)
    if fee(tx) < 0
        return false
    end
    for i in 1:length(tx.inputs)
        if !verify(tx, i - 1)
            return false
        end
    end
    return true
end

"""
Signs the input using the private key
"""
function txsigninput(tx::Tx, input_index::Integer, keypair::KeyPair)
    z = to_int(sig_hash(tx, input_index))
    sig = ECDSA.sign(keypair, z)
    txpushsignature(tx, input_index, z, sig, keypair.𝑄)
end

"""
Append Signature to the Script Pubkey of TxIn at index
"""
function txpushsignature(tx::Tx, input_index::Integer, z::Integer, sig::ECDSA.Signature, pubkey::Secp256k1.Point)
    der = serialize(sig)
    append!(der, bytes(SIGHASH_ALL))
    sec = serialize(pubkey)
    script_sig = Script([der, sec])
    tx.tx_ins[input_index + 1].script_sig = script_sig
    return verify(tx, input_index)
end
