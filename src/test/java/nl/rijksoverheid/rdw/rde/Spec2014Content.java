package nl.rijksoverheid.rdw.rde;

import nl.rijksoverheid.rdw.rde.crypto.CryptoKeyConverter;
import org.bouncycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

public class Spec2014Content {

    //ChipAuthenticationInfo [protocol: id-CA-ECDH-AES-CBC-CMAC-256, version: 1, keyId: -]
    //ChipAuthenticationPublicKeyInfo [protocol: id-PK-ECDH, chipAuthenticationPublicKey: EC [brainpoolP320r1], keyId: -]
    //All bytes
    public static String DG14Hex = "6E8201D9318201D530820184060904007F000702020102308201753082011D06072A8648CE3D020130820110020101303406072A8648CE3D0101022900D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27305404283EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB40428520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A604510443BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E2061114FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1022900D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C5931102010103520004710DA6DAB5B770920D3D4D6807B02A13059BEFB4926E2D00CFDE4B4471571473A582934BBE92059800663578C83419E3563FE3E8AF3AE58B521D3741693C9CE19B312392CB00F59AF086863186706396300F060A04007F00070202030204020101300D060804007F00070202020201013012060A04007F0007020204020402010202010E30170606678108010105020101060A04007F00070101040103";
    public static String DG14_PubKey_Alg = "EC";


    /** File identifier for data group 2. Data group 2 contains face image data. */
    //First 500 bytes
    public static String DG2 = "758238587F618238530201017F6082384BA10E81010282010087020101880200085F2E82383646414300303130000000383600010000382800000000000000000000000000000000010101C102570103000000000000000C6A5020200D0A870A00000014667479706A703220000000006A70322000000158786D6C203C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D38223F3E0A3C434F4E54454E545F4445534352495054494F4E20786D6C6E733D22687474703A2F2F7777772E6A7065672E6F72672F6A70782F312E302F786D6C2220786D6C6E733A7873693D22687474703A2F2F7777772E77332E6F72672F323030312F584D4C536368656D612D696E7374616E636522207873693A736368656D614C6F636174696F6E3D22687474703A2F2F7777772E6A7065672E6F72672F6A70782F312E302F786D6C20687474703A2F2F7777772E6A7065672E6F72672F6D657461646174612F31353434342D322E787364223E0A3C50524F50455254593E0A3C4E414D453E414E3C2F4E414D453E0A3C56414C55453E3331323334353637383C2F56414C55453E0A3C2F50524F50455254593E0A3C2F434F4E54454E545F4445534352495054494F4E3E0A000000476A703268000000166968647200000257000001C10003070700000000000F636F6C720100";

    /** The security document. */
    //public static final String SOD = "";

    /** The data group presence list. */
    //public static final String COM = "";

    public static String DG14_PubKey = "308201753082011d06072a8648ce3d020130820110020101303406072a8648ce3d0101022900d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27305404283ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb40428520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a604510443bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1022900d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c5931102010103520004710da6dab5b770920d3d4d6807b02a13059befb4926e2d00cfde4b4471571473a582934bbe92059800663578c83419e3563fe3e8af3ae58b521d3741693c9ce19b312392cb00f59af086863186706396";
    public static String DG14_CA_ProtocolOID = "0.4.0.127.0.7.2.2.3.2.4";
    public static String DG14_PubKey_OID = "0.4.0.127.0.7.2.2.1.2";
    //public static String DG14_PubKey_ID = "id-PK-ECDH";

    public static PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, NoSuchProviderException {
        return CryptoKeyConverter.decodeAsn1DerX509ToPublicKey("EC", Hex.decode(DG14_PubKey));
        //return KeyFactory.getInstance("EC", new BouncyCastleProvider()).generatePublic(new X509EncodedKeySpec(Hex.decode(DG14_PubKey)));
    }

    public static AlgorithmParameterSpec getAlgorithmParameterSpec() throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, NoSuchProviderException {
        final PublicKey piccPublicKey = getPublicKey();

//        if (DG14_PubKey_Alg.equals(agreementAlg) && piccPublicKey instanceof DHPublicKey)
//            return ((DHPublicKey)piccPublicKey).getParams();

//        if (ECDH.equals(agreementAlg) && piccPublicKey instanceof ECPublicKey)
            return ((ECPublicKey)piccPublicKey).getParams();

//        throw new IllegalStateException("Cannot get parameters.");
    }}

