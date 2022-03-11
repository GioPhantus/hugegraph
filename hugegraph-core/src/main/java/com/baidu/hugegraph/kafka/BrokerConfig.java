/*
 * Copyright 2017 HugeGraph Authors
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.baidu.hugegraph.kafka;

import com.baidu.hugegraph.meta.MetaManager;

/**
 * BrokerConfig used to init producer and consumer
 * @author Scorpiour
 * @since 2022-01-18
 */
public class BrokerConfig {

    private static class ConfigHolder {
        public final static BrokerConfig instance = new BrokerConfig();
    }

    private BrokerConfig() {

    }

    public static BrokerConfig getInstance() {
        return ConfigHolder.instance;
    }

    public int getPartitionCount() {
        return 1;
    }

    public String getKafkaHost() {
        return MetaManager.instance().getKafkaBrokerHost();
    }

    public String getKafkaPort() {
        return MetaManager.instance().getKafkaBrokerPort();
    }

    public String getSyncGroupId() {
        return  "hugegraph-sync-consumer-group";
    }

    public String getSyncGroupInstanceId() {
        return "hugegraph-sync-consumer-instance-1";
    }

    public String getMutateGroupId() {
        return  "hugegraph-mutate-consumer-group";
    }

    public String getMutateGroupInstanceId() {
        return "hugegraph-mutate-consumer-instance-1";
    }

    public String getConfGroupId() {
        return "hugegraph-conf-consumer-group";
    }

    public String getConfGroupInstanceId() {
        return "hugegraph-conf-consumer-instance-1";
    }
    
}
