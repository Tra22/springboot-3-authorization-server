package com.tra21.authorization_server.mixin.deserialize;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.tra21.authorization_server.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UserDeserialize extends JsonDeserializer<User> {

    private static final TypeReference<List<SimpleGrantedAuthority>> SIMPLE_GRANTED_AUTHORITY_SET = new TypeReference<List<SimpleGrantedAuthority>>() {
    };

    /**
     * This method will create {@link org.springframework.security.core.userdetails.User} object. It will ensure successful object
     * creation even if password key is null in serialized json, because credentials may
     * be removed from the {@link org.springframework.security.core.userdetails.User} by invoking {@link org.springframework.security.core.userdetails.User#eraseCredentials()}. In
     * that case there won't be any password key in serialized json.
     * @param jp the JsonParser
     * @param ctxt the DeserializationContext
     * @return the user
     * @throws IOException if a exception during IO occurs
     * @throws JsonProcessingException if an error during JSON processing occurs
     */
    @Override
    public User deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        List<? extends GrantedAuthority> authorities = new ArrayList<>(mapper.convertValue(jsonNode.get("authorities"),
                SIMPLE_GRANTED_AUTHORITY_SET));
        JsonNode passwordNode = readJsonNode(jsonNode, "password");
        String username = readJsonNode(jsonNode, "username").asText();
        String password = passwordNode.asText("");
        boolean enabled = readJsonNode(jsonNode, "enabled").asBoolean();
        boolean accountNonExpired = readJsonNode(jsonNode, "acc_expired").asBoolean();
        boolean credentialsNonExpired = readJsonNode(jsonNode, "creds_expired").asBoolean();
        boolean accountNonLocked = readJsonNode(jsonNode, "acc_locked").asBoolean();
        User result = User.builder()
                .username(username)
                .password(password)
                .enabled(enabled)
                .accExpired(!accountNonExpired)
                .credsExpired(!credentialsNonExpired)
                .accLocked(!accountNonLocked)
                .build();
        if (passwordNode.asText(null) == null) {
            result.setPassword(null);
        }
        return result;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

}