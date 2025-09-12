from django.db import models
from django.utils import timezone
# Create your models here.


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


# --- Modelos para trackeo historico ---
class AgentFailedChecksSummary(models.Model):
    """
    Almacena el número total de checks fallidos para un agente en un momento específico.
    Este modelo es independiente y NO modifica los existentes.
    """
    agent_id = models.CharField(
        max_length=255,
        help_text="ID del agente Wazuh o AgenteTest",
        default=1,
        null=True,
        blank=True
    )
    failed_checks_count = models.PositiveIntegerField(
        help_text="Cantidad de checks fallidos registrados en este momento."
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora en que se registró este resumen."
    )

    class Meta:
        verbose_name = "Resumen de Checks Fallidos del Agente"
        verbose_name_plural = "Resúmenes de Checks Fallidos del Agente"
        ordering = ['-timestamp']


    def __str__(self):
        return f"Agente {self.agent_id} - Fallidos: {self.failed_checks_count} el {self.timestamp.strftime('%Y-%m-%d %H:%M')}"


class GlobalFailedChecksHistory(models.Model):
    """
    Almacena el total de checks fallidos en TODO el sistema en un momento específico.
    Esto permitirá rastrear cambios en el conteo global, incluso intradía.
    """
    total_failed_count = models.PositiveIntegerField(
        help_text="Cantidad total de checks fallidos en el sistema en este momento."
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora en que se registró este total global."
    )

    class Meta:
        verbose_name = "Historial Global de Checks Fallidos"
        verbose_name_plural = "Historiales Globales de Checks Fallidos"
        ordering = ['-timestamp'] # Ordena por fecha más reciente por defecto

    def __str__(self):
        return f"Total Fallidos: {self.total_failed_count} el {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
