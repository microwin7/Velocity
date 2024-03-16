/*
 * Copyright (C) 2023 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.velocitypowered.proxy.connection.util;

import com.velocitypowered.api.util.GameProfile;
import pro.gravit.launcher.base.Launcher;
import pro.gravit.launcher.base.events.request.CheckServerRequestEvent;
import pro.gravit.launcher.base.profiles.PlayerProfile;
import pro.gravit.launcher.base.profiles.Texture;
import pro.gravit.utils.helper.SecurityHelper;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class LauncherUtil {
    private static final String SESSION_ID_PROPERTY = "launcher_session_id";
    private static final String HARDWARE_ID_PROPERTY = "launcher_hardware_id";
    private static final String CUSTOM_PROPERTY_PREFIX = "launcher_";
    public static GameProfile makeGameProfile(CheckServerRequestEvent event) {
        PlayerProfile profile = event.playerProfile;
        List<GameProfile.Property> properties = new ArrayList<>();
        for (var e : profile.properties.entrySet()) {
            properties.add(new GameProfile.Property(e.getKey(), e.getValue(), ""));
        }
        if(event.sessionId != null) {
            properties.add(new GameProfile.Property(SESSION_ID_PROPERTY, event.sessionId, ""));
        }
        if(event.hardwareId != null) {
            properties.add(new GameProfile.Property(HARDWARE_ID_PROPERTY, event.hardwareId, ""));
        }
        if(event.sessionProperties != null) {
            for (var e : event.sessionProperties.entrySet()) {
                properties.add(new GameProfile.Property(CUSTOM_PROPERTY_PREFIX+e.getKey(), e.getValue(), ""));
            }
        }
        {
            String key = "textures";
            GameProfileTextureProperties textureProperty = new GameProfileTextureProperties();
            textureProperty.profileId = event.playerProfile.uuid.toString().replace("-", "");
            textureProperty.profileName = event.playerProfile.username;
            textureProperty.timestamp = System.currentTimeMillis();
            for (var texture : profile.assets.entrySet()) {
                textureProperty.textures.put(texture.getKey(), new GameProfileTextureProperties.GameTexture(texture.getValue()));
            }
            String value = Base64.getEncoder().encodeToString(Launcher.gsonManager.gson.toJson(textureProperty).getBytes(StandardCharsets.UTF_8));
            properties.add(new GameProfile.Property(key, value, ""));
        }
        return new GameProfile(profile.uuid, profile.username, properties);
    }

    public static class GameProfileTextureProperties {
        public long timestamp;
        public String profileId;
        public String profileName;
        public Map<String, GameTexture> textures = new HashMap<>();

        public static class GameTexture {
            public String url;
            public String hash;
            public Map<String, String> metadata;

            public GameTexture(String url, String hash, Map<String, String> metadata) {
                this.url = url;
                this.hash = hash;
                this.metadata = metadata;
            }

            public GameTexture(Texture texture) {
                this.url = texture.url;
                this.hash = texture.digest == null ? null : SecurityHelper.toHex(texture.digest);
                this.metadata = texture.metadata;
            }
        }
    }
}
