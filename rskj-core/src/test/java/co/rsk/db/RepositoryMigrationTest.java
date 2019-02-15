package co.rsk.db;

import co.rsk.cli.migration.UnitrieMigrationTool;
import co.rsk.core.RskAddress;
import co.rsk.trie.TrieConverter;
import co.rsk.trie.TrieImpl;
import co.rsk.trie.TrieStoreImpl;
import co.rsk.remasc.RemascTransaction;
import co.rsk.trie.*;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.TestUtils;
import org.ethereum.core.AccountState;
import org.ethereum.core.Repository;
import org.ethereum.crypto.Keccak256Helper;
import org.ethereum.datasource.HashMapDB;
import org.ethereum.db.MutableRepository;
import org.ethereum.vm.DataWord;
import org.ethereum.vm.PrecompiledContracts;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Iterator;

import static org.hamcrest.Matchers.is;

/**
 * Created by SerAdmin on 10/24/2018.
 */
public class RepositoryMigrationTest {

    // This is only to easily identify codes while debugging the trie.
    private final static byte[] CODE_PREFIX = new byte[]{-1,-1,-1,-1};
    // ORCHID_TRIE root: 3513db97e8e9afff71727bce4b2ac01ff3b874e4814cbb31828829b730fd7eca
    private final static byte[] ORCHID_TRIE = Hex.decode("00003513db97e8e9afff71727bce4b2ac01ff3b874e4814cbb31828829b730fd" +
            "7eca00000000001e00000020efca24d11fd5d95b6494378857d8e5856e69a78cb7bf7922c881fbb85ded0f1b000000460203000000" +
            "fdb14332af18a02002d98c7cd3162d3e9bf8b3661f50f4d69e83c184fcc02b5178662b1587771c16e780e7988169f42aa3d6121c06" +
            "bb5966459068ace8a93f15d900000020a5a9f4b9699784b58dde3e02788d1b6d58ecfc228bfa79503663b7113004748e0000004602" +
            "0100030000efca24d11fd5d95b6494378857d8e5856e69a78cb7bf7922c881fbb85ded0f1b3cbbb09e97eb85ba23ec1822eea6e057" +
            "f24e8d4f6d698c4fa671df3b574f380b00000020cacb5c364d3a0d4484b9f5799acd0280d284292b665855f4fa78d17630236dd000" +
            "000053f8518423c29b62890e33fafbdd50580000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" +
            "a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47000000020ea63ce51a897193cf2df6e91a9814fde" +
            "7d812cc53a9b99dbfb8883099857b170000000460201000300006132777b0dcb4885220f39408aa27c32693b518e691b38188b187a" +
            "25d6bdd398abbe1f7f9a1e84fe21b8587100c3b74a36e24233855f7f0f17e00ac1552bfd7e0000002056e81f171bcc55a6ff8345e6" +
            "92c0f86e5b48e01b996cadc001622fb5e363b4210000000602010000000000000020ee9767b78a6ce5f0d753af61043266f3e51399" +
            "10f0706da4d3210950b9f0695a00000053f851841e173a4c8908ac7230489e800000a011eb4d4c3a3be276820b4732166e96451235" +
            "7fc6c95344744621f3dce2140a4aa0ce76085c8aafb41c0ef1a91e297fa8f51dfd1738825a382077617aad9186897c000000204d98" +
            "ab7395024fcee86793faec0fb1407b8a988774caee979e55594af248094700000046020100030000ca3f6737ecaa4957fc253a90b9" +
            "7a69f6cd85b35c3315b4d96150a22495604ee80faed22496bdf7ae9aa65ac1a81fed84f23fa2d8f3313a725ad494df659b8fbb0000" +
            "002056232e967ce61fd9429822dc5ead2e878362903ce20fd7c1929abcd6ebd5170d00000046020100030000ea63ce51a897193cf2" +
            "df6e91a9814fde7d812cc53a9b99dbfb8883099857b170a5a9f4b9699784b58dde3e02788d1b6d58ecfc228bfa79503663b7113004" +
            "748e00000020abbe1f7f9a1e84fe21b8587100c3b74a36e24233855f7f0f17e00ac1552bfd7e000000460203000000fd75bcb031c9" +
            "ac0e57cee2317aa7e86bd653931258f8439957c552dda4297c33505c81c3a5275e6bf8ab5bada94c6e2debac620dbe95fd221fe082" +
            "36b9549c31b2000000206132777b0dcb4885220f39408aa27c32693b518e691b38188b187a25d6bdd398000000460203000000fd50" +
            "d1a9c0ef89eb1eaf1332eff254b9a3acf5238c5b68641a88ed3d8aa3e47b40cacb5c364d3a0d4484b9f5799acd0280d284292b6658" +
            "55f4fa78d17630236dd0000000204df7fe53ef2166b4ba5f874aff489b40a57d737981804e13038f87b9d6715d1400000046020300" +
            "0000fc98c8a8cb46de7b1920ea33b91c9d7eb5bb0621cf5a9cc8443e9ed70f81ab7e20551812f907afbe9f896f497ba3664b54ffce" +
            "94073bae5aa8a1c90810dc7953f4000000209c6d8278b9f2ad00ad97366bed668c68113ef3eb08d27d30ce6d12489c75c5e4000000" +
            "460203000000fbe855b478adef5ad6a85f42b0c259f07361a5fa5e76d323141ff4b75ed85b98c0ee9767b78a6ce5f0d753af610432" +
            "66f3e5139910f0706da4d3210950b9f0695a0000002090185a8f6e377afc0e92713ddeb385ba25ed63ad13f21c6a9c44919d952e37" +
            "2c00000046020100030000d6330ec57ade6c9f2d723985abc70790c752b5719e59ed7dc22d57c80f1f081aed8b70427b97a4b2aee2" +
            "e98cc8f88d7d1b8cbc1ef4e22827585ccc6e7467b32600000020551812f907afbe9f896f497ba3664b54ffce94073bae5aa8a1c908" +
            "10dc7953f400000053f85184e7f2bc408920a26da277a1280000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc00162" +
            "2fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470000000200faed22496bdf7ae9aa6" +
            "5ac1a81fed84f23fa2d8f3313a725ad494df659b8fbb000000460201000300002628411db3608a02b233dfc11c22c118b4331eeb04" +
            "0d6a119b899a08eacc88182bea7e6337e2cfc8b2a5fd0468ba7b66442526e9ab81ae459211c0b00e04cdba0000002090f0aaabb52c" +
            "f5345d6a248edb78970db4f8f4157334c969133636473d962a6b00000053f85184f1d00c2d8907c0860e5a80dc0000a056e81f171b" +
            "cc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7b" +
            "fad8045d85a470000000203cbbb09e97eb85ba23ec1822eea6e057f24e8d4f6d698c4fa671df3b574f380b00000047020100030001" +
            "009c6d8278b9f2ad00ad97366bed668c68113ef3eb08d27d30ce6d12489c75c5e45a452145b2730e85950ee225954945f40b3350c9" +
            "99c7e4fbfc2742eac5ab3cbc00000020d6330ec57ade6c9f2d723985abc70790c752b5719e59ed7dc22d57c80f1f081a0000004602" +
            "03000000fb1b767eb1e51fab7620a9c0db80be314e384ff1e62502a1d3ff6f00e1d4735b603747803acb776e564ed21b3df0cc9b7b" +
            "9a020081239cb5eaf9fbbc09fe158339000000202adde0f4259adf28ad6319a20c04208de869d01fc80a88fac327ef8dd6b396b400" +
            "000053f851841feff205892fd03576f6b6880000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" +
            "a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47000000020afd73bf33a6607a7ee747603b26f016b" +
            "f4c1e7a0b3e500cc2ffc10a8974efb2300000053f851840102a0fd8914542ba12a337c0000a07a6bf06e8e84f90933b79bf84ff452" +
            "42eb04c9677f18cb0704836ad9467e0f96a02328404cb3d202860b72aac53ab103d38c365b60331824d80d164f6921e27a32000000" +
            "205a452145b2730e85950ee225954945f40b3350c999c7e4fbfc2742eac5ab3cbc000000460203000000fbb9f067deb59063bb101c" +
            "c49e1570b7bb8ad19e97cb0fcf831a150aeda4f892202adde0f4259adf28ad6319a20c04208de869d01fc80a88fac327ef8dd6b396" +
            "b4000000205c81c3a5275e6bf8ab5bada94c6e2debac620dbe95fd221fe08236b9549c31b200000053f85184705801718918650127" +
            "cc3dc80000a0d575306f01546673a74fceec78818c646a408915ed93f0731aaa8fa3283de615a08be9da6943e5bf840b8ffaaa5f88" +
            "203ca01a5c609c2f9c6e427258f9f274eefe000000202bea7e6337e2cfc8b2a5fd0468ba7b66442526e9ab81ae459211c0b00e04cd" +
            "ba000000460203000000fd6c47ec9caf640a114e6c7c7e0e98f83f05f3cd8d9497d8f7bea56ea64dd507587aa9422af22e8c3d77b7" +
            "aa096944a729a8532464631bdcb729021bdf4351937100000020ca3f6737ecaa4957fc253a90b97a69f6cd85b35c3315b4d96150a2" +
            "2495604ee8000000470201000300010090185a8f6e377afc0e92713ddeb385ba25ed63ad13f21c6a9c44919d952e372c4df7fe53ef" +
            "2166b4ba5f874aff489b40a57d737981804e13038f87b9d6715d1400000020ed8b70427b97a4b2aee2e98cc8f88d7d1b8cbc1ef4e2" +
            "2827585ccc6e7467b326000000460203000000fb4b0ac9a996daf435c502bffa00cb111e7cd57348ee9c72b323148f37edcb6400af" +
            "d73bf33a6607a7ee747603b26f016bf4c1e7a0b3e500cc2ffc10a8974efb23000000207aa9422af22e8c3d77b7aa096944a729a853" +
            "2464631bdcb729021bdf4351937100000053f85184c47fa07489221920e76a48b40000a05aebe7d8638c97d07675c9788d96105320" +
            "f67b48d81ce34b43c31a8e0f60a2d9a0395139c01d04c4b144535c688055fa4baab703373af103800733b60b3d857f610000002035" +
            "13db97e8e9afff71727bce4b2ac01ff3b874e4814cbb31828829b730fd7eca0000004602010003000056232e967ce61fd9429822dc" +
            "5ead2e878362903ce20fd7c1929abcd6ebd5170d4d98ab7395024fcee86793faec0fb1407b8a988774caee979e55594af248094700" +
            "000020662b1587771c16e780e7988169f42aa3d6121c06bb5966459068ace8a93f15d900000053f851843af01d4f891a9dfe6a920c" +
            "cc0000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0" +
            "e500b653ca82273b7bfad8045d85a470000000203747803acb776e564ed21b3df0cc9b7b9a020081239cb5eaf9fbbc09fe15833900" +
            "000053f85184ca02da2a8912f939c99edab80000a0db06ef684dcdf23ad7c5d1c1afdcf642d087e4c9643e52365589efe8d3bf0c62" +
            "a0560ebca6bb0dc143e6ba187c62c764d01345f4008828066b71c0f10c49d08a4a000000202628411db3608a02b233dfc11c22c118" +
            "b4331eeb040d6a119b899a08eacc8818000000460203000000fd1471e9e8a8ced25fd7fe0dacc8484996ded2a96d8890ce96168b23" +
            "87174120c090f0aaabb52cf5345d6a248edb78970db4f8f4157334c969133636473d962a6b");
    private static final byte[] ORCHID_TRIE_CONTAINING_REMASC_ACCOUNT = Hex.decode("00007ce41845ab31e2b9df73df3037736b925e66202506fa95f7fdbe6dd2aa5e5f86000000000006000000203751c11ece97e219c009f4a6d3c4a723f770432fb50770fe10261641e383903b00000046f8440180a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470000000207ce41845ab31e2b9df73df3037736b925e66202506fa95f7fdbe6dd2aa5e5f8600000046020100030000f32816cbedb5ff40e48b70e3328663810abce71eba7f4b53087ed14f8e5f9460a31cc2bcaf6326c864510ac3b06b3d19f014ae677b9e441da6d33bdaf13a2eab00000020f32816cbedb5ff40e48b70e3328663810abce71eba7f4b53087ed14f8e5f9460000000460203000000ffc23972da1468d621757392437ecff845a61e5e3f1db6c3fc99e571a7bc1ffcc07ddca309a9955d4e8e500770d8f8c73ad3aca292217884bd21abd764b6122a7c0000002056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42100000006020100000000000000207ddca309a9955d4e8e500770d8f8c73ad3aca292217884bd21abd764b6122a7c00000046f8448080a01748476f798f2104d23f1b05ef472d5a4bd1a5f9ad4341a91b3aa724aa45fa8fa0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47000000020a31cc2bcaf6326c864510ac3b06b3d19f014ae677b9e441da6d33bdaf13a2eab000000460203000000ff786cf13cf43c50286c8c8453051f02facc25ef68efaccb23ff2d53c0c97993143751c11ece97e219c009f4a6d3c4a723f770432fb50770fe10261641e383903b");

    @Test
    public void test1Simple() {
        Repository repository = createRepository(new TrieStoreImpl(new HashMapDB()));

        Repository track = repository.startTracking();

        TestUtils.getRandom().setSeed(0);
        int maxAccounts = 10;
        int maxStorageRows = 5;
        for(int i=0;i<maxAccounts ;i++) {
            // Create random accounts/contracts
            RskAddress addr = TestUtils.randomAddress();
            track.createAccount(addr);
            // Set some random balance
            AccountState a = track.getAccountState(addr);
            a.setNonce(TestUtils.randomBigInteger(4));
            // Balance between 1 and 100 SBTC
            a.addToBalance(TestUtils.randomCoin(18, 1000));
            track.updateAccountState(addr,a);
            if (i>=maxAccounts/2) {
                // half of them are contracts
                track.setupContract(addr);
                for (int s = 0; s < maxStorageRows; s++) {
                    track.addStorageBytes(addr, TestUtils.randomDataWord(), TestUtils.randomBytes(TestUtils.getRandom().nextInt(40) + 1));
                }
                track.saveCode(addr,randomCode(60));
            }
        }

        track.commit();
        TrieConverter tc = new TrieConverter();
        byte[] oldRoot = tc.getOrchidAccountTrieRoot((TrieImpl) repository.getMutableTrie().getTrie());
        Trie atrie = UnitrieMigrationTool.orchidTrieDeserialize(ORCHID_TRIE);

        Assert.assertThat(Hex.toHexString(oldRoot), is(atrie.getHash().toHexString()));
    }

    @Test
    @Ignore("We need to replicate original contract storage in the unitrie")
    public void testWithRemascTransaction() {
        Repository repository = createRepository(new TrieStoreImpl(new HashMapDB()));
        repository.createAccount(PrecompiledContracts.REMASC_ADDR);
        repository.createAccount(RemascTransaction.REMASC_ADDRESS);

        AccountState remascSenderAccountState = repository.getAccountState(RemascTransaction.REMASC_ADDRESS);
        remascSenderAccountState.setNonce(BigInteger.ONE);
        repository.updateAccountState(RemascTransaction.REMASC_ADDRESS, remascSenderAccountState);

        repository.addStorageBytes(PrecompiledContracts.REMASC_ADDR, new DataWord(Hex.decode("0000000000000000000000000000000000000000000000007369626c696e6773")), Hex.decode("c0"));

        Trie remascAccountOnlyOrchidTrie = UnitrieMigrationTool.orchidTrieDeserialize(ORCHID_TRIE_CONTAINING_REMASC_ACCOUNT);

        Iterator<Trie.IterationElement> orchidIterator = remascAccountOnlyOrchidTrie.getInOrderIterator();
        while (orchidIterator.hasNext()) {
            Trie.IterationElement next = orchidIterator.next();
            if (next.getExpandedPath().length == Keccak256Helper.DEFAULT_SIZE) {
                OldAccountState oldAccountState = new OldAccountState(next.getNode().getValue());
                System.out.println(oldAccountState);
            }
        }
        Trie unitrie = repository.getMutableTrie().getTrie();

        Iterator<Trie.IterationElement> unitrieIterator = unitrie.getInOrderIterator();
        while (unitrieIterator.hasNext()) {
            Trie.IterationElement next = unitrieIterator.next();
            if (next.getExpandedPath().length == 248 || next.getExpandedPath().length == 96) {
                Trie node = next.getNode();
                System.out.println(node);
            }
        }

        TrieConverter converter = new TrieConverter();
        byte[] convertedRoot = converter.getOrchidAccountTrieRoot((TrieImpl) unitrie);
        Assert.assertThat(Hex.toHexString(convertedRoot), is(remascAccountOnlyOrchidTrie.getHash().toHexString()));
    }

    private byte[] randomCode(int maxSize) {
        int length = TestUtils.getRandom().nextInt(maxSize- CODE_PREFIX.length-1)+1;
        return TestUtils.concat(CODE_PREFIX,TestUtils.randomBytes(length));
    }

    private static Repository createRepository(TrieStore store) {
        return new MutableRepository(new MutableTrieImpl(new TrieImpl(store, true)));
    }

}
