flowchart LR

L <-- Auth login HTTP flow----> AAPC
X -- Sideband HTTP w/ encrypted session data --> BASS

subgraph user [User]
L[Web Browser ]
end

subgraph one [APM A]
direction LR
subgraph AAPC [ACCESS_POLICY_COMPLETED]
Y{If Access Policy result = Allow} -- True --> X[Generate sideband]
    Y -- False --> W(Exit gracefully)
end
end

subgraph two [APM B]
direction LR
subgraph BASS [ACCESS_SESSION_STARTED]
    B{Decrypt X-sessionData header}
    B -- Success -->  E[Debug log decrypted session data]
    D[Log decryption error and return]

    E -->  G[set ACCESS::session data for each decrypted session data
    ]
    B -- Failure --> D
end
subgraph ACCESS_POLICY_COMPLETED
    G --> J[Debug log]
    J --> K[Drop request]
end
end