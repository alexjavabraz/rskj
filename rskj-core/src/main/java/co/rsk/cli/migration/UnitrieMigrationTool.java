/*
 * This file is part of RskJ
 * Copyright (C) 2019 RSK Labs Ltd.
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

package co.rsk.cli.migration;

import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.remasc.RemascTransaction;
import co.rsk.trie.*;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.CommonConfig;
import org.ethereum.config.DefaultConfig;
import org.ethereum.config.SystemProperties;
import org.ethereum.config.net.TestNetConfig;
import org.ethereum.core.AccountState;
import org.ethereum.core.Block;
import org.ethereum.core.Repository;
import org.ethereum.crypto.Keccak256Helper;
import org.ethereum.datasource.HashMapDB;
import org.ethereum.datasource.KeyValueDataSource;
import org.ethereum.db.BlockStore;
import org.ethereum.db.ByteArrayWrapper;
import org.ethereum.db.MutableRepository;
import org.ethereum.util.*;
import org.ethereum.vm.DataWord;
import org.ethereum.vm.PrecompiledContracts;

import java.util.*;
import java.util.stream.Collectors;

import static org.ethereum.crypto.HashUtil.EMPTY_TRIE_HASH;

public class UnitrieMigrationTool {

    static {
        SystemProperties.DONOTUSE_blockchainConfig = new TestNetConfig();
    }

    private final CommonConfig commonConfig;
    private final KeyValueDataSource orchidContractDetailsDataStore;
    private final KeyValueDataSource orchidContractsStorage;
    private final BlockStore blockStore;
    private final TrieStore orchidAccountsTrieStore;
    private final String orchidDatabase;
    private final Map<RskAddress, TrieStore> contractStoreCache = new HashMap<>();
    private final Map<ByteArrayWrapper, RskAddress> addressHashes;
    private final TrieConverter trieConverter;
    private final Map<ByteArrayWrapper, byte[]> keccak256Cache;

    public static void main(String[] args) {
        UnitrieMigrationTool migrationTool = new UnitrieMigrationTool("/Users/diegoll/Documents/databases/test");
        Repository newRepository = migrationTool.migrateRepository("/Users/diegoll/Documents/databases/new");
        System.out.println(Hex.toHexString(newRepository.getRoot()));
    }

    public UnitrieMigrationTool(String orchidDatabase) {
        this.orchidDatabase = orchidDatabase;
        this.commonConfig = new CommonConfig();
        this.orchidContractDetailsDataStore = commonConfig.makeDataSource("details", orchidDatabase);
        this.orchidContractsStorage = commonConfig.makeDataSource("contracts-storage", orchidDatabase);
        DefaultConfig defaultConfig = new DefaultConfig();
        this.blockStore = defaultConfig.buildBlockStore(orchidDatabase);
        this.orchidAccountsTrieStore = new CachedTrieStore(new TrieStoreImpl(commonConfig.makeDataSource("state", orchidDatabase)));
        this.trieConverter = new TrieConverter();
        this.keccak256Cache = new HashMap<>();
        this.addressHashes = orchidContractDetailsDataStore.keys().stream()
                .filter(accountAddress -> accountAddress.length == 20)
                .collect(
                    Collectors.toMap(accountAddress -> ByteUtil.wrap(Keccak256Helper.keccak256(accountAddress)),
                    RskAddress::new
                )
            );
        this.addressHashes.put(ByteUtil.wrap(Keccak256Helper.keccak256(PrecompiledContracts.REMASC_ADDR.getBytes())), PrecompiledContracts.REMASC_ADDR);
        this.addressHashes.put(ByteUtil.wrap(Keccak256Helper.keccak256(RemascTransaction.REMASC_ADDRESS.getBytes())), RemascTransaction.REMASC_ADDRESS);
    }

    private Repository migrateRepository(String newDatabase) {
        Trie unitrie = new TrieImpl(new TrieStoreImpl(commonConfig.makeDataSource("state", newDatabase)), true);
        long maxNumber = blockStore.getMaxNumber();
        for (int height = 0; height < maxNumber; height++) { // genesis must be handled independently
            Block currentBlock = blockStore.getChainBlockByNumber(height);
            byte[] orchidStateRoot = currentBlock.getStateRoot();
            Trie orchidAccountsTrie = orchidAccountsTrieStore.retrieve(orchidStateRoot);
            Trie partialUnitrie = buildPartialUnitrie(orchidAccountsTrie, orchidContractDetailsDataStore);
            unitrie = unitrie.add(partialUnitrie);
            if (height % 50 == 0) {
                System.out.printf("======================================= %07d ========================================\n", height);
                System.out.printf("Orchid state root:\t\t%s\nConverted Unitrie root:\t%s\n",
                        Hex.toHexString(orchidStateRoot),
                        Hex.toHexString(trieConverter.getOrchidAccountTrieRoot((TrieImpl) unitrie))
                );
            }
        }
        return new MutableRepository(unitrie);
    }

    private Trie buildPartialUnitrie(Trie orchidAccountsTrie, KeyValueDataSource detailsDataStore) {
        Repository partialRepository = new MutableRepository(new TrieImpl(new TrieStoreImpl(new HashMapDB()), true));
        Iterator<Trie.IterationElement> orchidAccountsTrieIterator = orchidAccountsTrie.getPreOrderIterator();
        while (orchidAccountsTrieIterator.hasNext()) {
            Trie.IterationElement orchidAccountsTrieElement = orchidAccountsTrieIterator.next();
            byte[] currentElementExpandedPath = orchidAccountsTrieElement.getExpandedPath();
            if (currentElementExpandedPath.length == Keccak256Helper.DEFAULT_SIZE) {
                byte[] hashedAddress = PathEncoder.encode(currentElementExpandedPath);
                OldAccountState oldAccountState = new OldAccountState(orchidAccountsTrieElement.getNode().getValue());
                AccountState accountState = new AccountState(oldAccountState.getNonce(), oldAccountState.getBalance());
                RskAddress accountAddress = addressHashes.get(ByteUtil.wrap(hashedAddress));
                partialRepository.createAccount(accountAddress);
                partialRepository.updateAccountState(accountAddress, accountState);
                byte[] contractData = detailsDataStore.get(accountAddress.getBytes());
                byte[] codeHash = oldAccountState.getCodeHash();
                byte[] accountStateRoot = oldAccountState.getStateRoot();
                if (contractData != null && !Arrays.equals(accountStateRoot, EMPTY_TRIE_HASH)) {
                    migrateContract(accountAddress, partialRepository, contractData, codeHash, accountStateRoot);
                }
            }
        }
        return partialRepository.getMutableTrie().getTrie();
    }

    private void migrateContract(RskAddress accountAddress, Repository currentRepository, byte[] contractData, byte[] accountCodeHash, byte[] stateRoot) {
        ArrayList<RLPElement> rlpData = RLP.decode2(contractData);
        RLPList rlpList = (RLPList) rlpData.get(0);
        RLPElement rlpCode = rlpList.get(3);
        byte[] code = rlpCode.getRLPData();

        RLPItem rlpAddress = (RLPItem) rlpList.get(0);
        RLPItem rlpIsExternalStorage = (RLPItem) rlpList.get(1);
        RLPItem rlpStorage = (RLPItem) rlpList.get(2);
        byte[] rawAddress = rlpAddress.getRLPData();
        RskAddress contractAddress;
        if (Arrays.equals(rawAddress, new byte[] { 0x00 })) {
            contractAddress = PrecompiledContracts.REMASC_ADDR;
        } else {
            contractAddress = new RskAddress(rawAddress);
        }
        byte[] external = rlpIsExternalStorage.getRLPData();
        byte[] root = rlpStorage.getRLPData();
        Trie contractStorageTrie;
        if (external != null && external.length > 0 && external[0] == 1) {
            //FIXME(diegoll): review co.rsk.db.ContractStorageStoreFactory#addressIsDedicated
            TrieStore contractTrieStore = contractStoreCache.computeIfAbsent(
                    contractAddress,
                    address -> new CachedTrieStore(new TrieStoreImpl(commonConfig.makeDataSource("details-storage/" + address, orchidDatabase)))
            );
            contractStorageTrie = contractTrieStore.retrieve(root);
        } else {
            contractStorageTrie = orchidTrieDeserialize(root);
        }
        contractStorageTrie = contractStorageTrie.getSnapshotTo(new Keccak256(stateRoot));

        RLPList rlpKeys = (RLPList) rlpList.get(4);
        boolean initialized = false;
        for (RLPElement rlpKey : rlpKeys) {
            byte[] rawKey = rlpKey.getRLPData();
            byte[] storageKey = keccak256Cache.computeIfAbsent(ByteUtil.wrap(rawKey), key -> Keccak256Helper.keccak256(key.getData()));
            byte[] value = contractStorageTrie.get(storageKey);
            if (value != null) {
                if (!initialized) {
                    currentRepository.setupContract(accountAddress);
                    initialized = true;
                }
                currentRepository.addStorageBytes(contractAddress, new DataWord(rawKey), value);
            }
        }

        if (code != null) {
            if (!Arrays.equals(accountCodeHash, Keccak256Helper.keccak256(code))) {
                // mati-fix (ref: org.ethereum.db.DetailsDataStore#get)
                code = orchidContractsStorage.get(accountCodeHash);
            }
            currentRepository.saveCode(accountAddress, code);
        }
    }

    public static Trie orchidTrieDeserialize(byte[] bytes) {
        final int keccakSize = Keccak256Helper.DEFAULT_SIZE_BYTES;
        int expectedSize = Short.BYTES + keccakSize;
        if (expectedSize > bytes.length) {
            throw new IllegalArgumentException(
                    String.format("Expected size is: %d actual size is %d", expectedSize, bytes.length));
        }

        byte[] root = Arrays.copyOfRange(bytes, Short.BYTES, expectedSize);
        TrieStore store = orchidTrieStoreDeserialize(bytes, expectedSize, new HashMapDB());

        Trie newTrie = store.retrieve(root);

        if (newTrie == null) {
            throw new IllegalArgumentException(String.format("Deserialized storage doesn't contain expected trie: %s", Hex.toHexString(root)));
        }

        return newTrie;
    }

    private static TrieStore orchidTrieStoreDeserialize(byte[] bytes, int offset, KeyValueDataSource ds) {
        int current = offset;
        current += Short.BYTES; // version

        int nkeys = readInt(bytes, current);
        current += Integer.BYTES;

        for (int k = 0; k < nkeys; k++) {
            int lkey = readInt(bytes, current);
            current += Integer.BYTES;
            if (lkey > bytes.length - current) {
                throw new IllegalArgumentException(String.format(
                        "Left bytes are too short for key expected:%d actual:%d total:%d",
                        lkey, bytes.length - current, bytes.length));
            }
            byte[] key = Arrays.copyOfRange(bytes, current, current + lkey);
            current += lkey;

            int lvalue = readInt(bytes, current);
            current += Integer.BYTES;
            if (lvalue > bytes.length - current) {
                throw new IllegalArgumentException(String.format(
                        "Left bytes are too short for value expected:%d actual:%d total:%d",
                        lvalue, bytes.length - current, bytes.length));
            }
            byte[] value = Arrays.copyOfRange(bytes, current, current + lvalue);
            current += lvalue;
            ds.put(key, value);
        }

        return new TrieStoreImpl(ds);
    }

    // this methods reads a int as dataInputStream + byteArrayInputStream
    private static int readInt(byte[] bytes, int position) {
        final int LAST_BYTE_ONLY_MASK = 0x000000ff;
        int ch1 = bytes[position] & LAST_BYTE_ONLY_MASK;
        int ch2 = bytes[position+1] & LAST_BYTE_ONLY_MASK;
        int ch3 = bytes[position+2] & LAST_BYTE_ONLY_MASK;
        int ch4 = bytes[position+3] & LAST_BYTE_ONLY_MASK;
        if ((ch1 | ch2 | ch3 | ch4) < 0) {
            throw new IllegalArgumentException(
                    String.format("On position %d there are invalid bytes for a short value %s %s %s %s",
                            position, ch1, ch2, ch3, ch4));
        } else {
            return (ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4);
        }
    }

    private class CachedTrieStore implements TrieStore {

        private final TrieStore parent;
        private final Map<Keccak256, Trie> triesCache;
        private final Map<ByteArrayWrapper, byte[]> valueCache;

        private CachedTrieStore(TrieStore parent) {
            this.parent = parent;
            this.triesCache = new HashMap<>();
            this.valueCache = new HashMap<>();
        }

        @Override
        public void save(Trie trie) {
            triesCache.put(trie.getHash(), trie);
            parent.save(trie);
        }

        @Override
        public Trie retrieve(byte[] hash) {
            return triesCache.computeIfAbsent(new Keccak256(hash), key -> parent.retrieve(hash));
        }

        @Override
        public byte[] retrieveValue(byte[] hash) {
            return valueCache.computeIfAbsent(ByteUtil.wrap(hash), key -> parent.retrieveValue(hash));
        }
    }
}
