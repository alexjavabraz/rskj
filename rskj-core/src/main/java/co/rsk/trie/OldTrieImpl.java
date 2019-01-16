package co.rsk.trie;

/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


        import co.rsk.crypto.Keccak256;
import org.ethereum.crypto.Keccak256Helper;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.function.BiFunction;
        
        

/**
 * OldTrieImpl is the trie node.
 *
 *
 */
public class OldTrieImpl extends TrieImpl {

    private static final int MESSAGE_HEADER_LENGTH = 2 + Short.BYTES * 2;

    // default constructor, no secure
    public OldTrieImpl() {
        super();
    }

    protected OldTrieImpl(byte[] encodedSharedPath,
                       int sharedPathLength, byte[] value, TrieImpl[] nodes,
                       Keccak256[] hashes, TrieStore store,
                       int valueLength,byte[] valueHash, boolean isSecure) {

        super(encodedSharedPath,sharedPathLength, value, nodes,
                hashes, store,valueLength, valueHash, isSecure);
    }

    public OldTrieImpl(boolean isSecure) {
        super(isSecure);
    }

    @Override
    protected TrieImpl getInstance(TrieStore store, boolean isSecure){
        return new OldTrieImpl(null, 0, null, null, null, store, 0, null, isSecure);
    }

    @Override
    protected TrieImpl getInstance(byte[] encodedSharedPath, int sharedPathLength, byte[] value, TrieImpl[] nodes,
                           Keccak256[] hashes, TrieStore store, int valueLength, byte[] valueHash, boolean isSecure) {
        return new OldTrieImpl(encodedSharedPath, sharedPathLength, value, nodes, hashes, store, valueLength, valueHash, isSecure);
    }

    /**
     * toMessage serialize the node to bytes. Used to persist the node in a key-value store
     * like levelDB or redis.
     *
     * The serialization includes:
     * - arity: byte
     * - bits with present hashes: two bytes (example: 0x0203 says that the node has
     * hashes at index 0, 1, 9 (the other subnodes are null)
     * - present hashes: 32 bytes each
     * - associated value: remainder bytes (no bytes if null)
     *
     * @return a byte array with the serialized info
     */
    @Override
    public byte[] toMessage() {
        int lvalue = this.valueLength;
        //int nnodes = this.getNodeCount();
        int lshared = this.sharedPathLength;
        int lencoded = getEncodedPathLength(lshared);
        boolean hasLongVal = this.hasLongValue();

        int bits = 0;
        int nnodes = 0;

        for (int k = 0; k < ARITY; k++) {
            Keccak256 nodeHash = this.getHash(k);

            if (nodeHash == null) {
                continue;
            }
            nnodes++;
            bits |= 1 << k;
        }

        ByteBuffer buffer = ByteBuffer.allocate(
                MESSAGE_HEADER_LENGTH +
//                        (lshared > 0 ? lencoded:0) + // TODO: check if lencoded is 0 when lshared is zero
                        (lshared > 0 ? lencoded:0) + // TODO: check if lencoded is 0 when lshared is zero
                        nnodes * Keccak256Helper.DEFAULT_SIZE_BYTES +
                        (hasLongVal ? Keccak256Helper.DEFAULT_SIZE_BYTES : lvalue)); //TODO check lvalue == 0 case

        buffer.put((byte) ARITY);

        byte flags = 0;

        if (this.isSecure) {
            flags |= 1;
        }

        if (hasLongVal) {
            flags |= 2;
        }

        buffer.put(flags);
        buffer.putShort((short) bits);
        buffer.putShort((short) lshared);

        if (lshared > 0) {
            buffer.put(encodedSharedPath);
        }

        for (int k = 0; k < ARITY; k++) {
            Keccak256 nodeHash = this.getHash(k);

            if (nodeHash == null) {
                continue;
            }
            try {
                buffer.put(nodeHash.getBytes());
            } catch (Exception e) {
                System.out.println(e);
            }
        }

        if (lvalue > 0) {
            if (hasLongVal) {
                buffer.put(this.getValueHash());
            }
            else {
                buffer.put(this.getValue());
            }
        }

        return buffer.array();
    }

    @Override
    public BiFunction<byte[], TrieStore, Trie> fromMessageFunction() {
        return OldTrieImpl::fromMessage;
    }

    public static OldTrieImpl fromMessage(byte[] message, TrieStore store) {
        if (message == null) {
            return null;
        }

        return fromMessage(message, 0, message.length, store);
    }


    private static OldTrieImpl fromMessage(byte[] message, int position, int msglength, TrieStore store) {
        if (message == null) {
            return null;
        }

        ByteArrayInputStream bstream = new ByteArrayInputStream(message, position, msglength);
        DataInputStream istream = new DataInputStream(bstream);

        try {
            int arity = istream.readByte();

            if (arity != ARITY) {
                throw new IllegalArgumentException(INVALID_ARITY);
            }

            int flags = istream.readByte();
            boolean isSecure = (flags & 0x01) == 1;
            boolean hasLongVal = (flags & 0x02) == 2;
            int bhashes = istream.readShort();
            int lshared = istream.readShort();

            int nhashes = 0;
            int lencoded = TrieImpl.getEncodedPathLength(lshared);

            byte[] encodedSharedPath = null;

            if (lencoded > 0) {
                encodedSharedPath = new byte[lencoded];
                if (istream.read(encodedSharedPath) != lencoded) {
                    throw new EOFException();
                }
            }

            Keccak256[] hashes = new Keccak256[arity];

            for (int k = 0; k < arity; k++) {
                if ((bhashes & (1 << k)) == 0) {
                    continue;
                }

                byte[] nodeHash = new byte[Keccak256Helper.DEFAULT_SIZE_BYTES];

                if (istream.read(nodeHash) != Keccak256Helper.DEFAULT_SIZE_BYTES) {
                    throw new EOFException();
                }

                hashes[k] = new Keccak256(nodeHash);
                nhashes++;
            }

            int offset = MESSAGE_HEADER_LENGTH + lencoded + nhashes * Keccak256Helper.DEFAULT_SIZE_BYTES;
            byte[] value = null;
            int lvalue;
            byte[] valueHash = null;

            if (hasLongVal) {
                valueHash = new byte[Keccak256Helper.DEFAULT_SIZE_BYTES];

                if (istream.read(valueHash) != Keccak256Helper.DEFAULT_SIZE_BYTES) {
                    throw new EOFException();
                }

                value = store.retrieveValue(valueHash);
                lvalue = value.length;
            }
            else {
                lvalue = msglength - offset;

                if (lvalue > 0) {
                    value = new byte[lvalue];
                    if (istream.read(value) != lvalue) {
                        throw new EOFException();
                    }
                }
            }

            OldTrieImpl trie = new OldTrieImpl(encodedSharedPath, lshared, value, null,
                    hashes, store,lvalue,valueHash, isSecure);

            if (store != null) {
                trie.saved = true;
            }

            return trie;
        } catch (IOException ex) {
            logger.error(ERROR_CREATING_TRIE, ex);
            panicProcessor.panic(PANIC_TOPIC, ERROR_CREATING_TRIE +": " + ex.getMessage());
            throw new TrieSerializationException(ERROR_CREATING_TRIE, ex);
        }
    }
}
