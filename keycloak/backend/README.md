# Nastavení Keycloak (verze 26.1.0)

## Vytvoření Realmu

1. Vlevo nahoře klikněte na **Create realm**.
2. Do pole **Realm name** zadejte `test`.
3. Klikněte na **Create**.

## Vytvoření Klienta

1. V menu vyberte **Clients**.
2. Klikněte na **Create client**.
3. Do pole **Client ID** zadejte `fastapi-app`.
4. Zapněte **Client authentication** a zbytek nechte ve výchozím nastavení.
5. Klikněte na **Save**.

## Přidání Role

1. V menu vyberte **Clients**.
2. Vyberte klienta `fastapi-app`.
3. Klikněte na záložku **Roles**.
4. Klikněte na **Create role**.
5. Do pole **Role Name** zadejte název role (například `user`).
6. Klikněte na **Save**.

## Vytvoření Skupiny

1. V menu vyberte **Groups**.
2. Klikněte na **Create group**.
3. Do pole **Name** zadejte název skupiny (například `admin_group`).
4. Klikněte na **Save**.
5. Pro přiřazení uživatelů ke skupině vyberte skupinu a v záložce **Members** klikněte na **Add member**.

### Přidání Mapperu pro Skupiny

1. V menu vyberte **Clients**.
2. Vyberte klienta `fastapi-app`.
3. Klikněte na záložku **Client scopes** a poté vyberte `fastapi-app-dedicated`.
4. Klikněte na tlačítko **Add mapper** a vyberte **By configuration**.
5. Vyberte **Group Membership**.
6. Do pole **Name** zadejte `Group Membership`.
7. Důležité je hlavně zadat **Token Claim Name**, aby se vůbec mělo co zobrazovat v samotném tokenu. Např. **groups**.
8. Klikněte na **Save**.

## Přidání Uživatelských Atributů

1. V menu vyberte **Realm settings**.
2. Vyberte **User profile**
3. Klikněte na tlačítko **Create attribute**.
4. Do pole **Attribute [Name]** zadejte název atributu (například `department`).
5. Upravte zbytek dle libosti
6. Klikněte na **Create**.

### Přidání Mapperu pro Atributy

1. V menu vyberte **Clients**.
2. Vyberte klienta `fastapi-app`.
3. Klikněte na záložku **Client scopes** a poté vyberte `fastapi-app-dedicated`.
4. Klikněte na tlačítko **Add mapper** a vyberte **By configuration**.
5. Vyberte **User Attribute**.
6. Do pole **Name** zadejte `department`.
7. Vyberte `department` atribut.
8. Důležité je hlavně zadat **Token Claim Name**, aby se vůbec mělo co zobrazovat v samotném tokenu.
9. Klikněte na **Save**.

Poznámka: atributy se dají namapovat i lokálně jen na daný client, stejně tak jako role
