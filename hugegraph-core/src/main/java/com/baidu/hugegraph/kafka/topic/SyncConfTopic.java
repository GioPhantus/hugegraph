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
 * under the License.PS
 */


package com.baidu.hugegraph.kafka.topic;

/**
 * Sync etcd service config
 */
public class SyncConfTopic extends TopicBase<String, String> {

    public final static String TOPIC = "hugegraph-sync-conf";

    protected SyncConfTopic(String key, String value, int partition) {
        super(key, value, TOPIC, partition);
    }
    
}
