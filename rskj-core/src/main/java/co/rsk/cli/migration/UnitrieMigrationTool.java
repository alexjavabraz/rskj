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
    private final TrieStore orchidContractsTrieStore;
    private final BlockStore blockStore;
    private final TrieStore orchidAccountsTrieStore;
    private final String orchidDatabase;
    private final Map<RskAddress, TrieStore> contractStoreCache = new HashMap<>();
    private final Map<ByteArrayWrapper, RskAddress> addressHashes;
    private final TrieConverter trieConverter;
    private final Map<ByteArrayWrapper, byte[]> keccak256Cache;

    public static void main(String[] args) {
        UnitrieMigrationTool migrationTool = new UnitrieMigrationTool("/Users/diegoll/Documents/databases/mainnet");
        byte[] lastStateRoot = migrationTool.migrateRepository(100);
        System.out.println(Hex.toHexString(lastStateRoot));
    }

    public UnitrieMigrationTool(String orchidDatabase) {
        this.orchidDatabase = orchidDatabase;
        this.commonConfig = new CommonConfig();
        this.orchidContractDetailsDataStore = commonConfig.makeDataSource("details", orchidDatabase);
        this.orchidContractsStorage = commonConfig.makeDataSource("contracts-storage", orchidDatabase);
        this.orchidContractsTrieStore = new CachedTrieStore(new TrieStoreImpl(orchidContractsStorage));
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

    private byte[] migrateRepository(long rewindCount) {
        MutableRepository unitrieRepository = new MutableRepository(new TrieImpl(new TrieStoreImpl(new HashMapDB()), true));
        long maxNumber = blockStore.getMaxNumber();
        byte[] lastStateRoot = null;
        for (long height = maxNumber - rewindCount; height < maxNumber; height++) {
            System.out.printf("======================================= %07d ========================================\n", height);
            Block currentBlock = blockStore.getChainBlockByNumber(height);
            byte[] orchidStateRoot = currentBlock.getStateRoot();
            Trie orchidAccountsTrie = orchidAccountsTrieStore.retrieve(orchidStateRoot);
            buildPartialUnitrie(orchidAccountsTrie, orchidContractDetailsDataStore, unitrieRepository);

            lastStateRoot = unitrieRepository.getRoot();
            byte[] orchidMigratedStateRoot = trieConverter.getOrchidAccountTrieRoot((TrieImpl) unitrieRepository.getMutableTrie().getTrie());
            if (!Arrays.equals(orchidStateRoot, orchidMigratedStateRoot)) {
                System.out.printf("\nOrchid state root:\t\t%s\nConverted Unitrie root:\t%s\n",
                        Hex.toHexString(orchidStateRoot),
                        Hex.toHexString(orchidMigratedStateRoot)
                );
                throw new IllegalStateException("Not matching state root");
            } else {
                System.out.println("Matched state root");
            }
        }
        return lastStateRoot;
    }

    private void buildPartialUnitrie(Trie orchidAccountsTrie, KeyValueDataSource detailsDataStore, Repository repository) {
        int accountsToLog = 500;
        int accountsCounter = 0;
        System.out.printf("(x = %d accounts): ", accountsToLog);
        Iterator<Trie.IterationElement> orchidAccountsTrieIterator = orchidAccountsTrie.getPreOrderIterator();
        while (orchidAccountsTrieIterator.hasNext()) {
            Trie.IterationElement orchidAccountsTrieElement = orchidAccountsTrieIterator.next();
            byte[] currentElementExpandedPath = orchidAccountsTrieElement.getExpandedPath();
            if (currentElementExpandedPath.length == Keccak256Helper.DEFAULT_SIZE) {
                accountsCounter++;
                byte[] hashedAddress = PathEncoder.encode(currentElementExpandedPath);
                OldAccountState oldAccountState = new OldAccountState(orchidAccountsTrieElement.getNode().getValue());
                AccountState accountState = new AccountState(oldAccountState.getNonce(), oldAccountState.getBalance());
                RskAddress accountAddress = addressHashes.get(ByteUtil.wrap(hashedAddress));
                repository.createAccount(accountAddress);
                repository.updateAccountState(accountAddress, accountState);
                byte[] contractData = detailsDataStore.get(accountAddress.getBytes());
                byte[] codeHash = oldAccountState.getCodeHash();
                byte[] accountStateRoot = oldAccountState.getStateRoot();
                if (contractData != null && !Arrays.equals(accountStateRoot, EMPTY_TRIE_HASH)) {
                    migrateContract(accountAddress, repository, contractData, codeHash, accountStateRoot);
                }
                if (accountsCounter % accountsToLog == 0) {
                    System.out.print("x");
                }
            }
        }
        allValuesProcessed(orchidAccountsTrie, accountsCounter);
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
            // picco-fix (ref: co.rsk.db.ContractStorageStoreFactory#getTrieStore)
            contractStorageTrie = orchidContractsTrieStore.retrieve(root);
            if (contractStorageTrie == null) {
                TrieStore contractTrieStore = contractStoreCache.computeIfAbsent(
                        contractAddress,
                        address -> new CachedTrieStore(new TrieStoreImpl(commonConfig.makeDataSource("details-storage/" + address, orchidDatabase)))
                );
                contractStorageTrie = contractTrieStore.retrieve(root);
                if (contractStorageTrie == null) {
                    throw new IllegalStateException(String.format("Unable to find root %s for the contract %s", Hex.toHexString(root), contractAddress));
                }
            }
        } else {
            contractStorageTrie = orchidTrieDeserialize(root);
        }
        contractStorageTrie = contractStorageTrie.getSnapshotTo(new Keccak256(stateRoot));

        RLPList rlpKeys = (RLPList) rlpList.get(4);
        boolean initialized = false;
        int keysCount = rlpKeys.size();
        int keysToLog = 2000;
        boolean logKeysMigrationProgress = keysCount > keysToLog * 2;
        if (logKeysMigrationProgress) {
            System.out.printf("\nMigrating %s with %d keys\n(. = %d keys): ", contractAddress, rlpKeys.size(), keysToLog);
        }
        int migratedKeysCounter = 0;
        for (RLPElement rlpKey : rlpKeys) {
            byte[] rawKey = rlpKey.getRLPData();
            byte[] storageKey = keccak256Cache.computeIfAbsent(ByteUtil.wrap(rawKey), key -> Keccak256Helper.keccak256(key.getData()));
            byte[] value = contractStorageTrie.get(storageKey);
            if (value != null) {
                migratedKeysCounter++;
                if (!initialized) {
                    currentRepository.setupContract(accountAddress);
                    initialized = true;
                }
                if (logKeysMigrationProgress && migratedKeysCounter % keysToLog == 0) {
                    System.out.print(".");
                }
                currentRepository.addStorageBytes(contractAddress, new DataWord(rawKey), value);
            }
        }
        try {
            allValuesProcessed(contractStorageTrie, migratedKeysCounter);
        } catch (IllegalStateException ise) {
            throw new IllegalStateException(String.format("Error processing storage for contract %s", contractAddress), ise);
        }
        if (logKeysMigrationProgress) {
            System.out.println();
        }

        if (code != null) {
            if (!Arrays.equals(accountCodeHash, Keccak256Helper.keccak256(code))) {
                // mati-fix (ref: org.ethereum.db.DetailsDataStore#get)
                code = orchidContractsStorage.get(accountCodeHash);
            }
            currentRepository.saveCode(accountAddress, code);
        }
    }

    /**
     * Counts all nodes with value and checks it's equals to accountsCounter
     * @param currentTrie
     * @param accountsCounter
     */
    private void allValuesProcessed(Trie currentTrie, int expectedCount) {
        int valueCounter = 0;
        Iterator<Trie.IterationElement> inOrderIterator = currentTrie.getInOrderIterator();
        while (inOrderIterator.hasNext()) {
            Trie.IterationElement iterationElement = inOrderIterator.next();
            if (iterationElement.getNode().getValue() != null) {
                valueCounter++;
            }
        }
        if (valueCounter != expectedCount) {
            throw new IllegalStateException(String.format("Trie %s has %d values and we expected %d", currentTrie.getHash(), valueCounter, expectedCount));
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
