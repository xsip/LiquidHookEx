// Entity.cpp
#include <ExampleProcess/IEntity.h>
#include <cstdio>

CEntity::CEntity(const char* name, int health)
    : m_szName(name), m_nHealth(health) {
}

int CEntity::GetHealth() const {
    return m_nHealth;
}

void CEntity::SetHealth(int hp) {
    m_nHealth = hp;
}

const char* CEntity::GetName() const {
    return m_szName;
}

void CEntity::Update() {
    if (m_nHealth > 0)
        --m_nHealth;
    printf("[CEntity::Update] %s  hp=%d\n", m_szName, m_nHealth);
}