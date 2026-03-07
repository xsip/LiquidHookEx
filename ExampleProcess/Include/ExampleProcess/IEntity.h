// IEntity.h
#pragma once
#include <cstdint>

class IEntity {
public:
    virtual ~IEntity() = default;
    virtual int         GetHealth() const = 0;
    virtual void        SetHealth(int hp) = 0;
    virtual const char* GetName()  const = 0;
    virtual void        Update() = 0;
};

class CEntity : public IEntity {
public:
    explicit CEntity(const char* name, int health = 100);
    int         GetHealth() const override;
    void        SetHealth(int hp)  override;
    const char* GetName()  const   override;
    void        Update()           override;
private:
    const char* m_szName;
    int         m_nHealth;
};