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

package co.rsk.core;

import co.rsk.cli.CliArgs;
import co.rsk.config.*;
import co.rsk.core.bc.BlockChainImpl;
import co.rsk.core.bc.TransactionPoolImpl;
import co.rsk.crypto.Keccak256;
import co.rsk.db.RepositoryImpl;
import co.rsk.metrics.BlockHeaderElement;
import co.rsk.metrics.HashRateCalculator;
import co.rsk.metrics.HashRateCalculatorMining;
import co.rsk.metrics.HashRateCalculatorNonMining;
import co.rsk.mine.*;
import co.rsk.net.*;
import co.rsk.net.discovery.PeerExplorer;
import co.rsk.net.discovery.UDPServer;
import co.rsk.net.discovery.table.KademliaOptions;
import co.rsk.net.discovery.table.NodeDistanceTable;
import co.rsk.net.eth.MessageFilter;
import co.rsk.net.eth.MessageRecorder;
import co.rsk.net.eth.RskWireProtocol;
import co.rsk.net.eth.WriterMessageRecorder;
import co.rsk.net.sync.SyncConfiguration;
import co.rsk.rpc.*;
import co.rsk.rpc.modules.debug.DebugModule;
import co.rsk.rpc.modules.eth.*;
import co.rsk.rpc.modules.evm.EvmModule;
import co.rsk.rpc.modules.mnr.MnrModule;
import co.rsk.rpc.modules.personal.PersonalModule;
import co.rsk.rpc.modules.personal.PersonalModuleWalletDisabled;
import co.rsk.rpc.modules.personal.PersonalModuleWalletEnabled;
import co.rsk.rpc.modules.txpool.TxPoolModule;
import co.rsk.rpc.netty.*;
import co.rsk.scoring.PeerScoring;
import co.rsk.scoring.PeerScoringManager;
import co.rsk.scoring.PunishmentParameters;
import co.rsk.trie.Trie;
import co.rsk.trie.TrieStoreImpl;
import co.rsk.util.RskCustomCache;
import co.rsk.validators.*;
import org.apache.commons.collections4.CollectionUtils;
import org.ethereum.config.Constants;
import org.ethereum.config.SystemProperties;
import org.ethereum.config.net.RegTestConfig;
import org.ethereum.core.*;
import org.ethereum.core.genesis.BlockChainLoader;
import org.ethereum.core.genesis.GenesisLoader;
import org.ethereum.crypto.ECKey;
import org.ethereum.datasource.DataSourceWithCache;
import org.ethereum.datasource.KeyValueDataSource;
import org.ethereum.datasource.LevelDbDataSource;
import org.ethereum.db.IndexedBlockStore;
import org.ethereum.db.ReceiptStore;
import org.ethereum.db.ReceiptStoreImpl;
import org.ethereum.db.TrieStorePoolOnDisk;
import org.ethereum.facade.Ethereum;
import org.ethereum.listener.CompositeEthereumListener;
import org.ethereum.listener.EthereumListener;
import org.ethereum.net.EthereumChannelInitializerFactory;
import org.ethereum.net.NodeManager;
import org.ethereum.net.client.ConfigCapabilities;
import org.ethereum.net.client.PeerClient;
import org.ethereum.net.eth.handler.EthHandlerFactory;
import org.ethereum.net.eth.handler.EthHandlerFactoryImpl;
import org.ethereum.net.message.StaticMessages;
import org.ethereum.net.rlpx.Node;
import org.ethereum.net.server.ChannelManager;
import org.ethereum.net.server.EthereumChannelInitializer;
import org.ethereum.net.server.PeerServer;
import org.ethereum.net.server.PeerServerImpl;
import org.ethereum.rpc.Web3;
import org.ethereum.solidity.compiler.SolidityCompiler;
import org.ethereum.sync.SyncPool;
import org.ethereum.util.BuildInfo;
import org.ethereum.util.FileUtil;
import org.ethereum.validator.*;
import org.ethereum.vm.program.invoke.ProgramInvokeFactory;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.util.*;

import static java.util.Arrays.asList;
import static org.ethereum.db.IndexedBlockStore.BLOCK_INFO_SERIALIZER;

@Configuration
@ComponentScan({"co.rsk", "org.ethereum"})
public class RskFactory {

    private static final Logger logger = LoggerFactory.getLogger("general");

    @Bean
    public PeerScoringManager getPeerScoringManager(SystemProperties config) {
        int nnodes = config.scoringNumberOfNodes();

        long nodePunishmentDuration = config.scoringNodesPunishmentDuration();
        int nodePunishmentIncrement = config.scoringNodesPunishmentIncrement();
        long nodePunhishmentMaximumDuration = config.scoringNodesPunishmentMaximumDuration();

        long addressPunishmentDuration = config.scoringAddressesPunishmentDuration();
        int addressPunishmentIncrement = config.scoringAddressesPunishmentIncrement();
        long addressPunishmentMaximunDuration = config.scoringAddressesPunishmentMaximumDuration();

        boolean punishmentEnabled = config.scoringPunishmentEnabled();

        return new PeerScoringManager(
                () -> new PeerScoring(punishmentEnabled),
                nnodes,
                new PunishmentParameters(nodePunishmentDuration, nodePunishmentIncrement, nodePunhishmentMaximumDuration),
                new PunishmentParameters(addressPunishmentDuration, addressPunishmentIncrement, addressPunishmentMaximunDuration)
        );
    }

    @Bean
    public NodeBlockProcessor getNodeBlockProcessor(Blockchain blockchain, BlockStore blockStore,
                                                    BlockNodeInformation blockNodeInformation, BlockSyncService blockSyncService, SyncConfiguration syncConfiguration) {
        return new NodeBlockProcessor(blockStore, blockchain, blockNodeInformation, blockSyncService, syncConfiguration);
    }

    @Bean
    public SyncProcessor getSyncProcessor(Blockchain blockchain,
                                          BlockSyncService blockSyncService,
                                          PeerScoringManager peerScoringManager,
                                          ChannelManager channelManager,
                                          SyncConfiguration syncConfiguration,
                                          DifficultyCalculator difficultyCalculator,
                                          ProofOfWorkRule proofOfWorkRule) {

        // TODO(lsebrie): add new BlockCompositeRule(new ProofOfWorkRule(), blockTimeStampValidationRule, new ValidGasUsedRule());
        return new SyncProcessor(blockchain, blockSyncService, peerScoringManager, channelManager,
                syncConfiguration, proofOfWorkRule, difficultyCalculator);
    }

    @Bean
    public BlockSyncService getBlockSyncService(RskSystemProperties config,
                                                Blockchain blockchain,
                                                BlockStore store,
                                                BlockNodeInformation nodeInformation,
                                                SyncConfiguration syncConfiguration) {
            return new BlockSyncService(config, store, blockchain, nodeInformation, syncConfiguration);
    }

    @Bean
    public SyncPool getSyncPool(@Qualifier("compositeEthereumListener") EthereumListener ethereumListener,
                                Blockchain blockchain,
                                RskSystemProperties config,
                                NodeManager nodeManager) {
        return new SyncPool(ethereumListener, blockchain, config, nodeManager);
    }

    @Bean
    public Web3 getWeb3(Rsk rsk,
                        Blockchain blockchain,
                        TransactionPool transactionPool,
                        RskSystemProperties config,
                        MinerClient minerClient,
                        MinerServer minerServer,
                        MnrModule mnrModule,
                        PersonalModule personalModule,
                        EthModule ethModule,
                        EvmModule evmModule,
                        TxPoolModule txPoolModule,
                        DebugModule debugModule,
                        ChannelManager channelManager,
                        Repository repository,
                        PeerScoringManager peerScoringManager,
                        NetworkStateExporter networkStateExporter,
                        org.ethereum.db.BlockStore blockStore,
                        ReceiptStore receiptStore,
                        PeerServer peerServer,
                        BlockProcessor nodeBlockProcessor,
                        HashRateCalculator hashRateCalculator,
                        ConfigCapabilities configCapabilities,
                        BuildInfo buildInfo) {
        return new Web3RskImpl(
                rsk,
                blockchain,
                transactionPool,
                config,
                minerClient,
                minerServer,
                personalModule,
                ethModule,
                evmModule,
                txPoolModule,
                mnrModule,
                debugModule,
                channelManager,
                repository,
                peerScoringManager,
                networkStateExporter,
                blockStore,
                receiptStore,
                peerServer,
                nodeBlockProcessor,
                hashRateCalculator,
                configCapabilities,
                buildInfo
        );
    }

    @Bean
    public JsonRpcWeb3FilterHandler getJsonRpcWeb3FilterHandler(RskSystemProperties rskSystemProperties) {
        return new JsonRpcWeb3FilterHandler(rskSystemProperties.corsDomains(), rskSystemProperties.rpcHttpBindAddress(), rskSystemProperties.rpcHttpHost());
    }

    @Bean
    public JsonRpcWeb3ServerHandler getJsonRpcWeb3ServerHandler(Web3 web3Service, RskSystemProperties rskSystemProperties) {
        return new JsonRpcWeb3ServerHandler(web3Service, rskSystemProperties.getRpcModules());
    }

    @Bean
    public Web3WebSocketServer getWeb3WebSocketServer(
            RskSystemProperties rskSystemProperties,
            Ethereum ethereum,
            JsonRpcWeb3ServerHandler serverHandler,
            JsonRpcSerializer serializer) {
        EthSubscriptionNotificationEmitter emitter = new EthSubscriptionNotificationEmitter(ethereum, serializer);
        RskJsonRpcHandler jsonRpcHandler = new RskJsonRpcHandler(emitter, serializer);
        return new Web3WebSocketServer(
                rskSystemProperties.rpcWebSocketBindAddress(),
                rskSystemProperties.rpcWebSocketPort(),
                jsonRpcHandler,
                serverHandler
        );
    }

    @Bean
    public JsonRpcSerializer getJsonRpcSerializer() {
        return new JacksonBasedRpcSerializer();
    }

    @Bean
    public Web3HttpServer getWeb3HttpServer(RskSystemProperties rskSystemProperties,
                                            JsonRpcWeb3FilterHandler filterHandler,
                                            JsonRpcWeb3ServerHandler serverHandler) {
        return new Web3HttpServer(
            rskSystemProperties.rpcHttpBindAddress(),
            rskSystemProperties.rpcHttpPort(),
            rskSystemProperties.soLingerTime(),
            true,
            new CorsConfiguration(rskSystemProperties.corsDomains()),
            filterHandler,
            serverHandler
        );
    }

    @Bean
    public BlockChainImpl getBlockchain(BlockChainLoader blockChainLoader) {
        return blockChainLoader.loadBlockchain();
    }

    @Bean
    public TransactionPool getTransactionPool(org.ethereum.db.BlockStore blockStore,
                                        ReceiptStore receiptStore,
                                        org.ethereum.core.Repository repository,
                                        RskSystemProperties config,
                                        ProgramInvokeFactory programInvokeFactory,
                                        CompositeEthereumListener listener) {
        return new TransactionPoolImpl(
                blockStore,
                receiptStore,
                listener,
                programInvokeFactory,
                repository,
                config
        );
    }

    @Bean
    public SyncPool.PeerClientFactory getPeerClientFactory(SystemProperties config,
                                                           @Qualifier("compositeEthereumListener") EthereumListener ethereumListener,
                                                           EthereumChannelInitializerFactory ethereumChannelInitializerFactory) {
        return () -> new PeerClient(config, ethereumListener, ethereumChannelInitializerFactory);
    }

    @Bean
    public EthereumChannelInitializerFactory getEthereumChannelInitializerFactory(
            ChannelManager channelManager,
            RskSystemProperties config,
            CompositeEthereumListener ethereumListener,
            ConfigCapabilities configCapabilities,
            NodeManager nodeManager,
            EthHandlerFactory ethHandlerFactory,
            StaticMessages staticMessages,
            PeerScoringManager peerScoringManager) {
        return remoteId -> new EthereumChannelInitializer(
                remoteId,
                config,
                channelManager,
                ethereumListener,
                configCapabilities,
                nodeManager,
                ethHandlerFactory,
                staticMessages,
                peerScoringManager
        );
    }

    @Bean
    public Genesis getGenesis(RskSystemProperties config) {
        return GenesisLoader.loadGenesis(
                config.genesisInfo(),
                config.getBlockchainConfig().getCommonConstants().getInitialNonce(),
                true
        );
    }

    @Bean
    public MessageRecorder getMessageRecorder(RskSystemProperties config) {
        if (!config.hasMessageRecorderEnabled()) {
            return null;
        }

        String database = config.databaseDir();
        String filename = "messages";
        Path filePath = Paths.get(database).isAbsolute() ? Paths.get(database, filename) :
                Paths.get(System.getProperty("user.dir"), database, filename);

        String fullFilename = filePath.toString();
        MessageFilter filter = new MessageFilter(config.getMessageRecorderCommands());

        try {
            return new WriterMessageRecorder(
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    new FileOutputStream(fullFilename), StandardCharsets.UTF_8)), filter);
        }
        catch (IOException ex) {
            logger.error("Exception creating message recorder: ", ex);
            return null;
        }
    }

    @Bean
    public EthHandlerFactoryImpl.RskWireProtocolFactory getRskWireProtocolFactory(PeerScoringManager peerScoringManager,
                                                                                  MessageHandler messageHandler,
                                                                                  Blockchain blockchain,
                                                                                  RskSystemProperties config,
                                                                                  CompositeEthereumListener ethereumListener,
                                                                                  Genesis genesis,
                                                                                  MessageRecorder messageRecorder){
        return () -> new RskWireProtocol(config, peerScoringManager, messageHandler, blockchain, ethereumListener,
                                         genesis, messageRecorder);
    }

    @Bean
    public PeerServer getPeerServer(SystemProperties config,
                                    @Qualifier("compositeEthereumListener") EthereumListener ethereumListener,
                                    EthereumChannelInitializerFactory ethereumChannelInitializerFactory) {
        return new PeerServerImpl(config, ethereumListener, ethereumChannelInitializerFactory);
    }

    @Bean
    public Wallet getWallet(RskSystemProperties config) {
        if (!config.isWalletEnabled()) {
            logger.info("Local wallet disabled");
            return null;
        }

        logger.info("Local wallet enabled");
        KeyValueDataSource ds = new LevelDbDataSource("wallet", config.databaseDir());
        ds.init();
        return new Wallet(ds);
    }

    @Bean
    public PersonalModule getPersonalModuleWallet(RskSystemProperties config, Rsk rsk, Wallet wallet, TransactionPool transactionPool) {
        if (wallet == null) {
            return new PersonalModuleWalletDisabled();
        }

        return new PersonalModuleWalletEnabled(config, rsk, wallet, transactionPool);
    }

    @Bean
    public EthModuleWallet getEthModuleWallet(Wallet wallet) {
        if (wallet == null) {
            return new EthModuleWalletDisabled();
        }

        return new EthModuleWalletEnabled(wallet);
    }

    @Bean
    public EthModuleSolidity getEthModuleSolidity(RskSystemProperties config) {
        try {
            return new EthModuleSolidityEnabled(new SolidityCompiler(config));
        } catch (RuntimeException e) {
            // the only way we currently have to check if Solidity is available is catching this exception
            logger.debug("Solidity compiler unavailable", e);
            return new EthModuleSolidityDisabled();
        }
    }

    @Bean
    public EthModuleTransaction getEthModuleTransaction(
            RskSystemProperties config,
            Wallet wallet,
            TransactionPool transactionPool,
            MinerServer minerServer,
            MinerClient minerClient,
            Blockchain blockchain) {

        if (wallet == null) {
            return new EthModuleTransactionDisabled(config, transactionPool);
        }

        if (config.minerClientAutoMine()) {
            return new EthModuleTransactionInstant(config, wallet, transactionPool, minerServer, minerClient, blockchain);
        }

        return new EthModuleTransactionBase(config, wallet, transactionPool);
    }

    @Bean
    public MinerClient getMinerClient(RskSystemProperties config, Rsk rsk, MinerServer minerServer) {
        if (config.minerClientAutoMine()) {
            return new AutoMinerClient(minerServer);
        }

        return new MinerClientImpl(rsk, minerServer, config.minerClientDelayBetweenBlocks(), config.minerClientDelayBetweenRefreshes());
    }

    @Bean
    public SyncConfiguration getSyncConfiguration(RskSystemProperties config) {
        int expectedPeers = config.getExpectedPeers();
        int timeoutWaitingPeers = config.getTimeoutWaitingPeers();
        int timeoutWaitingRequest = config.getTimeoutWaitingRequest();
        int expirationTimePeerStatus = config.getExpirationTimePeerStatus();
        int maxSkeletonChunks = config.getMaxSkeletonChunks();
        int chunkSize = config.getChunkSize();
        return new SyncConfiguration(expectedPeers, timeoutWaitingPeers, timeoutWaitingRequest,
                expirationTimePeerStatus, maxSkeletonChunks, chunkSize);
    }

    @Bean
    public BlockStore getBlockStore(){
        return new BlockStore();
    }

    @Bean(name = "compositeEthereumListener")
    public CompositeEthereumListener getCompositeEthereumListener() {
        return new CompositeEthereumListener();
    }

    @Bean
    public TransactionGateway getTransactionGateway(
            ChannelManager channelManager,
            TransactionPool transactionPool,
            CompositeEthereumListener emitter){
        return new TransactionGateway(channelManager, transactionPool, emitter);
    }

    @Bean
    public BuildInfo getBuildInfo(ResourceLoader resourceLoader) {
        Properties props = new Properties();
        Resource buldInfoFile = resourceLoader.getResource("classpath:build-info.properties");
        try {
            props.load(buldInfoFile.getInputStream());
        } catch (IOException ioe) {
            logger.warn("build-info.properties file missing from classpath");
            logger.trace("build-info.properties file missing from classpath exception", ioe);
            return new BuildInfo("dev", "dev");
        }

        return new BuildInfo(props.getProperty("build.hash"), props.getProperty("build.branch"));
    }

    @Bean
    public MinerClock getMinerClock(RskSystemProperties config){
        return new MinerClock(config.getBlockchainConfig() instanceof RegTestConfig, Clock.systemUTC());
    }

    @Bean
    public org.ethereum.db.BlockStore blockStore(RskSystemProperties config) {
        return buildBlockStore(config.databaseDir());
    }

    @Bean
    public RskSystemProperties rskSystemProperties(CliArgs<NodeCliOptions, NodeCliFlags> cliArgs) {
        return new RskSystemProperties(new ConfigLoader(cliArgs));
    }

    @Bean
    public Repository repository(RskSystemProperties config) {
        String databaseDir = config.databaseDir();
        if (config.databaseReset()) {
            FileUtil.recursiveDelete(databaseDir);
            try {
                Files.createDirectories(FileUtil.getDatabaseDirectoryPath(databaseDir, "database"));
            } catch (IOException e) {
                logger.error("Could not re-create database directory");
            }
            logger.info("Database reset done");
        }

        return buildRepository(databaseDir, config.detailsInMemoryStorageLimit(), config.getStatesCacheSize());
    }

    @Bean
    public BlockParentDependantValidationRule blockParentDependantValidationRule(
            Repository repository,
            RskSystemProperties config,
            DifficultyCalculator difficultyCalculator) {
        BlockTxsValidationRule blockTxsValidationRule = new BlockTxsValidationRule(repository);
        BlockTxsFieldsValidationRule blockTxsFieldsValidationRule = new BlockTxsFieldsValidationRule();
        PrevMinGasPriceRule prevMinGasPriceRule = new PrevMinGasPriceRule();
        BlockParentNumberRule parentNumberRule = new BlockParentNumberRule();
        BlockDifficultyRule difficultyRule = new BlockDifficultyRule(difficultyCalculator);
        BlockParentGasLimitRule parentGasLimitRule = new BlockParentGasLimitRule(config.getBlockchainConfig().
                getCommonConstants().getGasLimitBoundDivisor());

        return new BlockParentCompositeRule(blockTxsFieldsValidationRule, blockTxsValidationRule, prevMinGasPriceRule, parentNumberRule, difficultyRule, parentGasLimitRule);
    }

    @Bean(name = "blockValidationRule")
    public BlockValidationRule blockValidationRule(
            org.ethereum.db.BlockStore blockStore,
            RskSystemProperties config,
            DifficultyCalculator difficultyCalculator,
            ProofOfWorkRule proofOfWorkRule) {
        Constants commonConstants = config.getBlockchainConfig().getCommonConstants();
        int uncleListLimit = commonConstants.getUncleListLimit();
        int uncleGenLimit = commonConstants.getUncleGenerationLimit();
        int validPeriod = commonConstants.getNewBlockMaxSecondsInTheFuture();
        BlockTimeStampValidationRule blockTimeStampValidationRule = new BlockTimeStampValidationRule(validPeriod);

        BlockParentGasLimitRule parentGasLimitRule = new BlockParentGasLimitRule(commonConstants.getGasLimitBoundDivisor());
        BlockParentCompositeRule unclesBlockParentHeaderValidator = new BlockParentCompositeRule(new PrevMinGasPriceRule(), new BlockParentNumberRule(), blockTimeStampValidationRule, new BlockDifficultyRule(difficultyCalculator), parentGasLimitRule);

        BlockCompositeRule unclesBlockHeaderValidator = new BlockCompositeRule(proofOfWorkRule, blockTimeStampValidationRule, new ValidGasUsedRule());

        BlockUnclesValidationRule blockUnclesValidationRule = new BlockUnclesValidationRule(config, blockStore, uncleListLimit, uncleGenLimit, unclesBlockHeaderValidator, unclesBlockParentHeaderValidator);

        int minGasLimit = commonConstants.getMinGasLimit();
        int maxExtraDataSize = commonConstants.getMaximumExtraDataSize();

        return new BlockCompositeRule(new TxsMinGasPriceRule(), blockUnclesValidationRule, new BlockRootValidationRule(), new RemascValidationRule(), blockTimeStampValidationRule, new GasLimitRule(minGasLimit), new ExtraDataRule(maxExtraDataSize));
    }

    @Bean
    public ReceiptStore receiptStore(RskSystemProperties config) {
        return buildReceiptStore(config.databaseDir());
    }

    @Bean
    public HashRateCalculator hashRateCalculator(RskSystemProperties rskSystemProperties, org.ethereum.db.BlockStore blockStore, MiningConfig miningConfig) {
        RskCustomCache<Keccak256, BlockHeaderElement> cache = new RskCustomCache<>(60000L);
        if (!rskSystemProperties.isMinerServerEnabled()) {
            return new HashRateCalculatorNonMining(blockStore, cache);
        }

        return new HashRateCalculatorMining(blockStore, cache, miningConfig.getCoinbaseAddress());
    }

    @Bean
    public MiningConfig miningConfig(RskSystemProperties rskSystemProperties) {
        return new MiningConfig(
                rskSystemProperties.coinbaseAddress(),
                rskSystemProperties.minerMinFeesNotifyInDollars(),
                rskSystemProperties.minerGasUnitInDollars(),
                rskSystemProperties.minerMinGasPrice(),
                rskSystemProperties.getBlockchainConfig().getCommonConstants().getUncleListLimit(),
                rskSystemProperties.getBlockchainConfig().getCommonConstants().getUncleGenerationLimit(),
                new GasLimitConfig(
                        rskSystemProperties.getBlockchainConfig().getCommonConstants().getMinGasLimit(),
                        rskSystemProperties.getTargetGasLimit(),
                        rskSystemProperties.getForceTargetGasLimit()
                )
        );
    }

    @Bean
    public NetworkStateExporter networkStateExporter(Repository repository) {
        return new NetworkStateExporter(repository);
    }


    @Bean(name = "minerServerBlockValidation")
    public BlockValidationRule minerServerBlockValidationRule(
            org.ethereum.db.BlockStore blockStore,
            RskSystemProperties config,
            DifficultyCalculator difficultyCalculator,
            ProofOfWorkRule proofOfWorkRule) {
        Constants commonConstants = config.getBlockchainConfig().getCommonConstants();
        int uncleListLimit = commonConstants.getUncleListLimit();
        int uncleGenLimit = commonConstants.getUncleGenerationLimit();

        BlockParentGasLimitRule parentGasLimitRule = new BlockParentGasLimitRule(commonConstants.getGasLimitBoundDivisor());
        BlockParentCompositeRule unclesBlockParentHeaderValidator = new BlockParentCompositeRule(new PrevMinGasPriceRule(), new BlockParentNumberRule(), new BlockDifficultyRule(difficultyCalculator), parentGasLimitRule);

        int validPeriod = commonConstants.getNewBlockMaxSecondsInTheFuture();
        BlockTimeStampValidationRule blockTimeStampValidationRule = new BlockTimeStampValidationRule(validPeriod);
        BlockCompositeRule unclesBlockHeaderValidator = new BlockCompositeRule(proofOfWorkRule, blockTimeStampValidationRule, new ValidGasUsedRule());

        return new BlockUnclesValidationRule(config, blockStore, uncleListLimit, uncleGenLimit, unclesBlockHeaderValidator, unclesBlockParentHeaderValidator);
    }

    @Bean
    public PeerExplorer peerExplorer(RskSystemProperties rskConfig) {
        ECKey key = rskConfig.getMyKey();
        Integer networkId = rskConfig.networkId();
        Node localNode = new Node(key.getNodeId(), rskConfig.getPublicIp(), rskConfig.getPeerPort());
        NodeDistanceTable distanceTable = new NodeDistanceTable(KademliaOptions.BINS, KademliaOptions.BUCKET_SIZE, localNode);
        long msgTimeOut = rskConfig.peerDiscoveryMessageTimeOut();
        long refreshPeriod = rskConfig.peerDiscoveryRefreshPeriod();
        long cleanPeriod = rskConfig.peerDiscoveryCleanPeriod();
        List<String> initialBootNodes = rskConfig.peerDiscoveryIPList();
        List<Node> activePeers = rskConfig.peerActive();
        if(CollectionUtils.isNotEmpty(activePeers)) {
            for(Node n : activePeers) {
                InetSocketAddress address = n.getAddress();
                initialBootNodes.add(address.getHostName() + ":" + address.getPort());
            }
        }
        return new PeerExplorer(initialBootNodes, localNode, distanceTable, key, msgTimeOut, refreshPeriod, cleanPeriod, networkId);
    }

    @Bean
    public UDPServer udpServer(PeerExplorer peerExplorer, RskSystemProperties rskConfig) {
        return new UDPServer(rskConfig.getBindAddress().getHostAddress(), rskConfig.getPeerPort(), peerExplorer);
    }

    @Bean
    public List<Transaction> transactionPoolTransactions() {
        return Collections.synchronizedList(new ArrayList<Transaction>());
    }

    @Bean
    public ParentBlockHeaderValidator parentHeaderValidator(RskSystemProperties config, DifficultyCalculator difficultyCalculator) {

        List<DependentBlockHeaderRule> rules = new ArrayList<>(asList(
                new ParentNumberRule(),
                new DifficultyRule(difficultyCalculator),
                new ParentGasLimitRule(config.getBlockchainConfig().getCommonConstants().getGasLimitBoundDivisor())
        ));

        return new ParentBlockHeaderValidator(rules);
    }

    public ReceiptStore buildReceiptStore(String databaseDir) {
        KeyValueDataSource ds = new LevelDbDataSource("receipts", databaseDir);
        ds.init();
        return new ReceiptStoreImpl(ds);
    }

    private Repository buildRepository(String databaseDir, int memoryStorageLimit, int statesCacheSize) {
        KeyValueDataSource ds = makeDataSource("state", databaseDir);
        KeyValueDataSource detailsDS = makeDataSource("details", databaseDir);

        if (statesCacheSize != 0) {
            ds = new DataSourceWithCache(ds, statesCacheSize);
        }

        return new RepositoryImpl(
                new Trie(new TrieStoreImpl(ds), true),
                detailsDS,
                new TrieStorePoolOnDisk(databaseDir),
                memoryStorageLimit
        );
    }

    public static org.ethereum.db.BlockStore buildBlockStore(String databaseDir) {
        File blockIndexDirectory = new File(databaseDir + "/blocks/");
        File dbFile = new File(blockIndexDirectory, "index");
        if (!blockIndexDirectory.exists()) {
            boolean mkdirsSuccess = blockIndexDirectory.mkdirs();
            if (!mkdirsSuccess) {
                logger.error("Unable to create blocks directory: {}", blockIndexDirectory);
            }
        }

        DB indexDB = DBMaker.fileDB(dbFile)
                .closeOnJvmShutdown()
                .make();

        Map<Long, List<IndexedBlockStore.BlockInfo>> indexMap = indexDB.hashMapCreate("index")
                .keySerializer(Serializer.LONG)
                .valueSerializer(BLOCK_INFO_SERIALIZER)
                .counterEnable()
                .makeOrGet();

        KeyValueDataSource blocksDB = new LevelDbDataSource("blocks", databaseDir);
        blocksDB.init();

        return new IndexedBlockStore(indexMap, blocksDB, indexDB);
    }

    private KeyValueDataSource makeDataSource(String name, String databaseDir) {
        KeyValueDataSource ds = new LevelDbDataSource(name, databaseDir);
        ds.init();
        return ds;
    }
}
