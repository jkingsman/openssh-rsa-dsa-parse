var assert = require('assert'),
    opensslParse = require('../index');

describe('opensslParse', function() {
  describe('RSATests', function () {
    var key = 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAIEAnQQg+9yF125mdeVg9Q72E2KI1zyYYs8CeeEAJtUoyAjCfxRLMhIhV3JzJAtCwa0+x74mTwfHJiWsUhua1rmRusKno2nxKDEkuc6E6McqixJCyKiZyIJ6LBHniKaIZkCOobeMVfak58FJJ5WFGbNITxWzF/39esv066C9WjrZ/XM= rsa-key-test';
    var rawKey = 'AAAAB3NzaC1yc2EAAAABJQAAAIEAnQQg+9yF125mdeVg9Q72E2KI1zyYYs8CeeEAJtUoyAjCfxRLMhIhV3JzJAtCwa0+x74mTwfHJiWsUhua1rmRusKno2nxKDEkuc6E6McqixJCyKiZyIJ6LBHniKaIZkCOobeMVfak58FJJ5WFGbNITxWzF/39esv066C9WjrZ/XM=';
    var concatByteArray = '000711511510445114115970001370001290157432251220133215110102117229962451424619981362156015298207212122503821340200819412720755018338711411536116619317362199190387971993837172822715421418514518619416716310524140493618520613223219942139186620016815320013012244172311361661361026414216118314085246164231193733914913325179727921179232532531222032442351601899058217253115'
    var testKey = new opensslParse(key);

    it('loads the key into byte array', function () {
      assert.equal(key, testKey.getKey());
    });

    it('returns the raw key', function () {
      assert.equal(rawKey, testKey.getData());
    });

    it('returns the byte array', function () {
      assert.equal(concatByteArray, testKey.getByteArray().join(""));
      assert.equal(true, Array.isArray(testKey.getByteArray()));
    });

    it('returns the key type string', function () {
      assert.equal('ssh-rsa', testKey.getKeyType());
    });

    it('returns the key length', function () {
      assert.equal('1024', testKey.getKeyLength());
    });

    it('returns the comment', function () {
      assert.equal('rsa-key-test', testKey.getComment());
    });
  });

  describe('DSATests', function () {
    var key = 'ssh-dss AAAAB3NzaC1kc3MAAACBAJOqXMiNqCSJY24EEhV41tddisXMy490ZjvZb0WZHTO8+uz9G3MVhfA48SFlmEVZkKsDDVqvqEroqW5gTXNzY5iJEtdxe/dVrLUA2jnLDU4TqRpyCBWd1xv35men/lylfuw7Sl97FdaU8pCR4RczPzgRCSBFuJwwMH3Q44ggN9g1AAAAFQDbf2CejPiEEE7ffc4796sLDEVjrQAAAIBsP17l1xsclTw9tIDdw6Dox+EY0pmMzzR2Wj77/j2rHSsUUP5IZqFYYQSo+MntmeWnEv615Vh0w7fs2AaArAKjrec65vlw2XTSBXxDTOsasSlRk8atYFiFPVW24sIgputqkwSLP1RcCSJE5IbYtoXTJ3/ffG3/oTUtOMBZ+Z5kzwAAAIBMvKMzWxaRbTWL2P+qLh+FJEVG+XZRC3xKQSCNoroiCNGXq0t7+Wk1DTmLlajUI50rNoIwhbkLvxV9itj3E6bEwIvLWBiwNkWS2SZ4rmyFnLMfKU8gkvbxA47z98r0HhfbXq62XZgQY4Vr49LceoKHqKf53IbzT2nlQ/tUvGSgUQ== dsa-key-test';
    var rawKey = 'AAAAB3NzaC1kc3MAAACBAJOqXMiNqCSJY24EEhV41tddisXMy490ZjvZb0WZHTO8+uz9G3MVhfA48SFlmEVZkKsDDVqvqEroqW5gTXNzY5iJEtdxe/dVrLUA2jnLDU4TqRpyCBWd1xv35men/lylfuw7Sl97FdaU8pCR4RczPzgRCSBFuJwwMH3Q44ggN9g1AAAAFQDbf2CejPiEEE7ffc4796sLDEVjrQAAAIBsP17l1xsclTw9tIDdw6Dox+EY0pmMzzR2Wj77/j2rHSsUUP5IZqFYYQSo+MntmeWnEv615Vh0w7fs2AaArAKjrec65vlw2XTSBXxDTOsasSlRk8atYFiFPVW24sIgputqkwSLP1RcCSJE5IbYtoXTJ3/ffG3/oTUtOMBZ+Z5kzwAAAIBMvKMzWxaRbTWL2P+qLh+FJEVG+XZRC3xKQSCNoroiCNGXq0t7+Wk1DTmLlajUI50rNoIwhbkLvxV9itj3E6bEwIvLWBiwNkWS2SZ4rmyFnLMfKU8gkvbxA47z98r0HhfbXq62XZgQY4Vr49LceoKHqKf53IbzT2nlQ/tUvGSgUQ==';
    var concatByteArray = '000711511510445100115115000129014717092200141168361379911041821120214215931381972042031431161025921711169153295118825023625327115211332405624133101152698914417131390175168742321691109677115115991521371821511312324785172181021857203137819169261148211572152724723010316725492165126236597495123212141482421441452252351635617932691841564848125208227136325521653000210219127961581402481321678223125206592471711112699917300012810863942292152728149606118012822119516023219922524210153140207521189062251254611712943208025472102161889741682482012371532291671825418122988116195183236216612817221631732315823024911221711621051246776235261774181147198173968813361851822261943216623510614741396384929346822813421618213321139127223124109255161534556192892491581002070001287618816351912214510953139216255170463113336697024911881111247465321411621863482091511717512324910553135713914916821235157435413048133185111912112513821624719166196192139203882417654691462173812017410813315617931417932146246241314224324720224430232199417418293152169913310722721022012213013516816724922013424379105229672518418810016081'
    var testKey = new opensslParse(key);

    it('loads the key into byte array', function () {
      assert.equal(key, testKey.getKey());
    });

    it('returns the raw key', function () {
      assert.equal(rawKey, testKey.getData());
    });

    it('returns the byte array', function () {
      assert.equal(concatByteArray, testKey.getByteArray().join(""));
      assert.equal(true, Array.isArray(testKey.getByteArray()));
    });

    it('returns the key type string', function () {
      assert.equal('ssh-dss', testKey.getKeyType());
    });

    it('returns the key length', function () {
      assert.equal('1024', testKey.getKeyLength());
    });

    it('returns the comment', function () {
      assert.equal('dsa-key-test', testKey.getComment());
    });
  });

  describe('Comment Failover', function () {
    var key = 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAIEAnQQg+9yF125mdeVg9Q72E2KI1zyYYs8CeeEAJtUoyAjCfxRLMhIhV3JzJAtCwa0+x74mTwfHJiWsUhua1rmRusKno2nxKDEkuc6E6McqixJCyKiZyIJ6LBHniKaIZkCOobeMVfak58FJJ5WFGbNITxWzF/39esv066C9WjrZ/XM=';
    var testKey = new opensslParse(key);

    it('returns null without a comment', function () {
      assert.equal(null, testKey.getComment());
    });
  });
});
