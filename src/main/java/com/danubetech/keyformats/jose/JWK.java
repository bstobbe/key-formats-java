package com.danubetech.keyformats.jose;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class JWK {
    private String kid;
    private String use;
    private String key_ops;
    private String alg;
    private String kty;
    private String crv;
    private String x5u;
    private String x5c;
    private String x5t;
    private String x;
    private String y;
    private String d;
    private String n;
    private String e;

    public JWK() {
    }

    /*
     * Serialization
     */

    private static final ObjectMapper objectMapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

    public static JWK fromJson(String json) throws IOException {
        return objectMapper.readValue(json, JWK.class);
    }

    public static JWK fromJson(Reader reader) throws IOException {
        return objectMapper.readValue(reader, JWK.class);
    }

    public static JWK fromMap(Map<String, Object> map) throws IOException {
        return objectMapper.convertValue(map, JWK.class);
    }

    public Map<String, Object> toMap() {
        return objectMapper.convertValue(this, LinkedHashMap.class);
    }

    public String toJson() {
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Cannot write JSON: " + ex.getMessage(), ex);
        }
    }

    @Deprecated
    public static JWK parse(Map<String, Object> json) {
        return objectMapper.convertValue(json, JWK.class);
    }

    @Deprecated
    public static JWK parse(String string) throws IOException {
        return objectMapper.readValue(new StringReader(string), JWK.class);
    }

    @Deprecated
    public String toJSONString() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    /*
     * Getters and setters
     */

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKey_ops() {
        return key_ops;
    }

    public void setKey_ops(String key_ops) {
        this.key_ops = key_ops;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getX5u() {
        return x5u;
    }

    public void setX5u(String x5u) {
        this.x5u = x5u;
    }

    public String getX5c() {
        return x5c;
    }

    public void setX5c(String x5c) {
        this.x5c = x5c;
    }

    public String getX5t() {
        return x5t;
    }

    public void setX5t(String x5t) {
        this.x5t = x5t;
    }

    public String getX() {
        return x;
    }

    @JsonIgnore
    public byte[] getXdecoded() {
        String x = this.getX();
        return x != null ? Base64.decodeBase64(x) : null;
    }

    public void setX(String x) {
        this.x = x;
    }

    public String getY() {
        return y;
    }

    @JsonIgnore
    public byte[] getYdecoded() {
        String y = this.getY();
        return y != null ? Base64.decodeBase64(y) : null;
    }

    public void setY(String y) {
        this.y = y;
    }

    public String getD() {
        return d;
    }

    public void setD(String d) {
        this.d = d;
    }

    @JsonIgnore
    public byte[] getDdecoded() {
        String d = this.getD();
        return d != null ? Base64.decodeBase64(d) : null;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }

    @JsonIgnore
    public byte[] getNdecoded() {
        String n = this.getN();
        return n != null ? Base64.decodeBase64(n) : null;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }

    @JsonIgnore
    public byte[] getEdecoded() {
        String e = this.getE();
        return e != null ? Base64.decodeBase64(e) : null;
    }

    /*
     * Object methods
     */

    @Override
    public String toString() {
        return "JWK{" +
                "kid='" + kid + '\'' +
                ", use='" + use + '\'' +
                ", key_ops='" + key_ops + '\'' +
                ", alg='" + alg + '\'' +
                ", kty='" + kty + '\'' +
                ", crv='" + crv + '\'' +
                ", x5u='" + x5u + '\'' +
                ", x5c='" + x5c + '\'' +
                ", x5t='" + x5t + '\'' +
                ", x='" + x + '\'' +
                ", y='" + y + '\'' +
                ", d='" + d + '\'' +
                ", n='" + n + '\'' +
                ", e='" + e + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWK jwk = (JWK) o;
        return Objects.equals(kid, jwk.kid) && Objects.equals(use, jwk.use) && Objects.equals(key_ops, jwk.key_ops) && Objects.equals(alg, jwk.alg) && Objects.equals(kty, jwk.kty) && Objects.equals(crv, jwk.crv) && Objects.equals(x5u, jwk.x5u) && Objects.equals(x5c, jwk.x5c) && Objects.equals(x5t, jwk.x5t) && Objects.equals(x, jwk.x) && Objects.equals(y, jwk.y) && Objects.equals(d, jwk.d) && Objects.equals(n, jwk.n) && Objects.equals(e, jwk.e);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kid, use, key_ops, alg, kty, crv, x5u, x5c, x5t, x, y, d, n, e);
    }
}
