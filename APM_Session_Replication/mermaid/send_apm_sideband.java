flowchart LR


LL --> H

subgraph user [User]
LL[Web Browser ]
end


direction LR
subgraph apmARI [Rule Init - on save or TMM restart]
direction LR
    B[Load variables & datagroup of APM inventory list]
    B --> C[Build peer APM target list - excludes self]
    C --> D{Safety check: was self identified and ignored?}
    D -- No --> E[Log critical error, stop replication]
    D -- Yes --> F[set final variable containing list of peer APM devices]
end
F <-.-> Z
subgraph apmHR [HTTP_REQUEST]
direction LR
    H{HTTP MRHSession cookie exists?}
    H -- No --> I
    H -- Yes --> J{Cookie valid length?}
    J -- No --> I
    J -- Yes --> L{Normal, Valid Session exists?}
    L -- Yes --> I
    L -- No --> N[Check for pointer access session using original MRHSession cookie value]
    N -- Not found --> I
    N -- Found --> P[Get new MRHSession value from pointer session]
    P --> Q[Replace original MRHSession cookie in HTTP request with MRHSession cookie value from pointer session ]
    Q --> I
    I[If Debug = log ; exit gracefully]
    AAPM[Normal APM Module]
    I --> AAPM
end
AAPM -.-> S
subgraph apmAPC [ACCESS_POLICY_COMPLETED]
direction LR
    S{Policy result is allow}
    S -- No --> T[If Debug = log ; exit gracefully]
    S -- Yes --> U[Create array of common APM variables
    -
    user-specified & customizable]
    U --> V[Add extra user-defined session variables to array:
    1. APM trust key
    2. Longer session idle timout for peer devices
    3. Original APM hostname
    4. Original APM session ID]
    V --> W[Serialize array as key=value pairs as new variable]
    W --> X[AES Encrypt & base64 encode the new variable]
    X --> Y[Format HTTP request with X-sessionData header containing encrypted session data]
    Y --> Z[For each peer APM target:]
    Z --> AA[Open TCP connection]
    AA --> AB{Connection success?}
    AB -- No --> AC[Log error message]
    AB -- Yes --> AD[Send HTTP request]
    AD --> AE{Send success?}
    AE -- No --> AC
    AE -- Yes --> AG[If Debug = Log bytes sent]
    end
