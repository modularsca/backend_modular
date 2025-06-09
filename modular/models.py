from django.db import models
from django.utils import timezone
# Create your models here.


class AgenteTest(models.Model):
    id = models.CharField(max_length=10, primary_key=True)
    name = models.CharField(max_length=250)
    ip = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    passed_policies = models.IntegerField(default=0)
    failed_policies = models.IntegerField(default=0)
    na_policies = models.IntegerField()
    last_scan = models.DateTimeField(null=True, blank=True)
    policy_name = models.CharField(max_length=250, null=True, blank=True)

    def __str__(self):
        return self.name


class PolicyChecksTest(models.Model):
    # Vinculamos al agente de prueba
    agent_test = models.ForeignKey(
        'AgenteTest', # Usar string si AgenteTest se define después, o el nombre de la clase si se define antes
        on_delete=models.CASCADE,
        related_name='policy_checks_test',
        help_text="Agente de prueba al que pertenece este check"
    )
    # Campos directamente del JSON de ejemplo
    check_id_in_policy = models.PositiveIntegerField(help_text="ID numérico del check dentro de la política de prueba")
    policy_id_test = models.CharField(max_length=255, db_index=True, help_text="ID de la política de prueba (e.g., laboratorio_computo_windows)")
    result = models.CharField(max_length=50, help_text="Resultado del check (passed, failed, etc.)")
    remediation = models.TextField(blank=True, help_text="Remediación sugerida")
    command = models.TextField(blank=True, help_text="Comando ejecutado")
    description = models.TextField(blank=True, help_text="Descripción del check")
    title = models.CharField(max_length=255, help_text="Título del check")
    condition = models.CharField(max_length=50, blank=True, help_text="Condición de evaluación (all, any, none)")
    rationale = models.TextField(null=True, blank=True, help_text="Justificación del check")
    # Guardamos compliance y rules como JSON para simplicidad en testing
    compliance_json = models.JSONField(default=list, help_text="Mapeo de cumplimiento (formato JSON)")
    rules_json = models.JSONField(default=list, help_text="Reglas del check (formato JSON)")
    # Timestamp de cuándo se guardó este dato de prueba
    date_recorded = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Test Check {self.check_id_in_policy} for Agent {self.agent_test.id} - Policy {self.policy_id_test} ({self.result})"

    class Meta:
        verbose_name = "Policy Check (Test Data)"
        verbose_name_plural = "Policy Checks (Test Data)"
        ordering = ['agent_test', 'policy_id_test', 'check_id_in_policy']
    

class Cve(models.Model):
    # ID del CVE, como 'CVE-2017-0144'
    id = models.CharField(max_length=50, primary_key=True, help_text="Identificador único del CVE (e.g., CVE-2017-0144)")
    # Riesgo calculado como entero (0-100)
    risk_percentage = models.PositiveIntegerField(null=True, blank=True, help_text="Riesgo calculado como porcentaje entero (0-100)")
    # Puedes añadir más campos si los necesitas, como descripción, enlace, etc.
    # description = models.TextField(blank=True)
    last_updated = models.DateTimeField(auto_now=True, help_text="Última vez que se actualizó el riesgo")

    def __str__(self):
        risk = f"{self.risk_percentage}%" if self.risk_percentage is not None else "N/A"
        return f"{self.id} (Riesgo: {risk})"

    class Meta:
        verbose_name = "CVE"
        verbose_name_plural = "CVEs"
        ordering = ['-risk_percentage', 'id'] # Ordenar por riesgo descendente por defecto


class CurrentFailedCheck(models.Model):
    """
    Almacena el estado actual de los checks que están fallidos para un agente/política.
    Mezcla datos de prueba y producción.
    """
    agent_id = models.CharField(
        max_length=255,
        db_index=True,
        help_text="ID del agente Wazuh o AgenteTest"
    )
    check_id = models.PositiveIntegerField(
        help_text="ID del check de política (ej: 1, 2, 3...)"
    )
    policy_id = models.CharField(
        max_length=255,
        db_index=True,
        help_text="ID de la política (ej: 'laboratorio_computo_windows', 'cis_win11')"
    )
    last_seen = models.DateTimeField(
        auto_now=True, # Se actualiza automáticamente cada vez que se guarda (incluso si no hay cambios)
        help_text="Timestamp de cuándo se confirmó por última vez que este check estaba fallido"
    )

    class Meta:
        # Clave única para evitar duplicados
        unique_together = ('agent_id', 'check_id', 'policy_id')
        verbose_name = "Check Fallido Actual"
        verbose_name_plural = "Checks Fallidos Actuales"
        ordering = ['agent_id', 'policy_id', 'check_id'] # Orden por defecto

    def __str__(self):
        return f"Agente {self.agent_id} - Pol {self.policy_id} - Check {self.check_id} Failed (Visto: {self.last_seen.strftime('%Y-%m-%d %H:%M')})"
